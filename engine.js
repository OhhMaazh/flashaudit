/* BI FUTURE — browser prototype engine.
 * CSV → column mapping → in-browser anonymisation (SHA-256 + salt) → deterministic checks.
 * Thresholds are the defaults of docs/referentiel-audit-funnel.md §5. No LLM, no network.
 * Prototype only: the production engine is the Python library described in docs/PROMPT.md.
 */
(function (root) {
  "use strict";
  var DAY = 864e5, NB = " ";
  var norm = function (s) { return String(s == null ? "" : s).toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, " ").trim(); };

  // ---------- formatting (French) ----------
  var fmt = {
    int: function (n) { return String(Math.round(n)).replace(/\B(?=(\d{3})+$)/g, NB); },
    pct: function (n, d) { return (d ? n.toFixed(d).replace(".", ",") : Math.round(n)) + NB + "%"; },
    eur: function (n) { return n >= 1e6 ? (n / 1e6).toFixed(n >= 1e7 ? 1 : 2).replace(".", ",") + NB + "M€" : n >= 1e3 ? fmt.int(n / 1e3) + NB + "k€" : fmt.int(n) + NB + "€"; },
    days: function (n) { return Math.round(n) + NB + "j"; },
    date: function (day) { var d = new Date(day); return d.getUTCDate() + NB + ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."][d.getUTCMonth()] + NB + d.getUTCFullYear(); }
  };

  // ---------- 1. CSV ----------
  function parseCSV(text) {
    text = text.replace(/^﻿/, "");
    var nl = text.indexOf("\n"), first = nl > 0 ? text.slice(0, nl) : text;
    var delim = [",", ";", "\t"].sort(function (a, b) { return first.split(b).length - first.split(a).length; })[0];
    var rows = [], row = [], cur = "", q = false;
    for (var i = 0; i < text.length; i++) {
      var c = text[i];
      if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
      else if (c === '"') q = true;
      else if (c === delim) { row.push(cur); cur = ""; }
      else if (c === "\n") { row.push(cur); rows.push(row); row = []; cur = ""; }
      else if (c !== "\r") cur += c;
    }
    if (cur !== "" || row.length) { row.push(cur); rows.push(row); }
    var header = (rows.shift() || []).map(function (h) { return h.trim(); });
    return { header: header, rows: rows.filter(function (r) { return r.some(function (v) { return v !== ""; }); }) };
  }

  // ---------- 2. column mapping (canonical schema, référentiel §2) ----------
  var FIELDS = [
    ["deal_id", "Identifiant du deal", /^(record id|deal id|id|identifiant|opportunity id|id de la transaction|id du deal|id de fiche( d informations)?)$/, false],
    ["deal_label", "Nom du deal", /(deal name|nom de la transaction|opportunity name|nom du deal|^titre|^title|^name|^nom)$/, true],
    ["created_at", "Date de création", /(create date|created|date de creation|creation date|add time|creee? le)/, false],
    ["closed_at", "Date de clôture réelle", /(closed date|won time|lost time|cloture reelle|closed at|gagnee? le|perdue? le)/, false],
    ["close_date", "Date de clôture", /(close date|date de fermeture|date de cloture|expected close|closing date)/, false],
    ["pipeline", "Pipeline", /^pipeline$/, false],
    ["status", "Statut", /^(status|statut|etat|deal status)$/, false],
    ["stage", "Étape", /(deal stage|stage|etape|phase|phase de la transaction)$/, false],
    ["amount", "Montant", /^(amount|montant|value|valeur|deal value)( in company currency)?$/, false],
    ["owner_id", "Commercial", /(owner|proprietaire|responsable|commercial)/, true],
    ["company_id", "Entreprise", /(company|entreprise|account|organisation|organization|societe)/, true],
    ["lost_reason", "Raison de perte", /(lost reason|raison de (la )?perte|motif de perte)/, false],
    ["source", "Source", /(source|origine|canal)/, false],
    ["segment", "Segment", /(segment|taille|secteur|industry)/, false],
    ["last_activity_at", "Dernière activité", /(last activity|derniere activite|last contacted)/, false]
  ];
  var ENTERED = /^(?:hs )?(?:date entered|date d entree(?: dans)?|date entree|stage entered|entered)\s+(.+)$/;
  var PII_HINT = /(e ?mail|phone|telephone|contact|prenom|first name|last name|adresse|address)/;

  function proposeMapping(parsed) {
    var used = {};
    return parsed.header.map(function (h, i) {
      var n = norm(h), sample = [], col = { index: i, source: h, field: null, stage: null, pii: false };
      for (var r = 0; r < parsed.rows.length && sample.length < 2; r++) if (parsed.rows[r][i]) sample.push(parsed.rows[r][i]);
      col.sample = sample;
      var m = n.match(ENTERED);
      if (m) { col.field = "stage_entered"; var quoted = h.match(/"([^"]+)"/); col.stage = (quoted ? quoted[1] : m[1]).replace(/\s*\([^)]*\)\s*$/, ""); }
      else for (var f = 0; f < FIELDS.length; f++) if (!used[FIELDS[f][0]] && FIELDS[f][2].test(n)) { col.field = FIELDS[f][0]; col.pii = FIELDS[f][3]; used[col.field] = 1; break; }
      if (col.field !== "stage_entered" && !(col.field && !col.pii && /date|amount|stage|pipeline|source/.test(col.field)) && (PII_HINT.test(n) || sample.some(function (v) { return /@.+\./.test(v); }))) col.pii = true;
      return col;
    });
  }
  function fieldLabel(f) { for (var i = 0; i < FIELDS.length; i++) if (FIELDS[i][0] === f) return FIELDS[i][1]; return f === "stage_entered" ? "Date d’entrée dans l’étape" : "Ignorée"; }
  function isPiiField(f) { for (var i = 0; i < FIELDS.length; i++) if (FIELDS[i][0] === f) return FIELDS[i][3]; return false; }
  var REQUIRED = ["created_at", "stage", "owner_id"];

  // ---------- 3. anonymisation: identifying values never leave this function in clear ----------
  function sha12(text) {
    return root.crypto.subtle.digest("SHA-256", new TextEncoder().encode(text)).then(function (buf) {
      return Array.prototype.slice.call(new Uint8Array(buf), 0, 6).map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join("");
    });
  }
  function parseDate(v) {
    if (!v) return null; v = String(v).trim(); var m;
    if ((m = v.match(/^(\d{4})-(\d{2})-(\d{2})/))) return Date.UTC(+m[1], m[2] - 1, +m[3]);
    if ((m = v.match(/^(\d{1,2})[\/.\-](\d{1,2})[\/.\-](\d{2,4})/))) { var d = +m[1], mo = +m[2], y = +m[3]; if (y < 100) y += 2000; if (mo > 12) { var t = d; d = mo; mo = t; } return Date.UTC(y, mo - 1, d); }
    if (/^\d{12,13}$/.test(v)) return Math.floor(+v / DAY) * DAY;
    var p = Date.parse(v); return isNaN(p) ? null : Math.floor(p / DAY) * DAY;
  }
  function parseAmount(v) {
    if (v == null || v === "") return null;
    var s = String(v).replace(/[^\d,.\-]/g, "");
    if (s.indexOf(",") >= 0 && s.indexOf(".") >= 0) s = s.lastIndexOf(",") > s.lastIndexOf(".") ? s.replace(/\./g, "").replace(",", ".") : s.replace(/,/g, "");
    else if (s.indexOf(",") >= 0) s = /,\d{1,2}$/.test(s) ? s.replace(",", ".") : s.replace(/,/g, "");
    var n = parseFloat(s); return isNaN(n) ? null : n;
  }
  function anonymize(parsed, cols, salt) {
    var vault = {}, cache = {}, jobs = [], hashed = 0;
    var piiCols = cols.filter(function (c) { return c.field && c.field !== "stage_entered" && c.pii; });
    parsed.rows.forEach(function (r) { piiCols.forEach(function (c) { var v = r[c.index]; if (v) { hashed++; if (!cache[v]) { cache[v] = 1; jobs.push(sha12(salt + "|" + v).then(function (h) { cache[v] = h; vault[h] = v; })); } } }); });
    return Promise.all(jobs).then(function () {
      var us = {};
      cols.forEach(function (c) { if (!c.field || !(c.field === "stage_entered" || /(_at|_date)$/.test(c.field))) return; for (var r = 0; r < parsed.rows.length; r++) { var m = /^(\d{1,2})[\/.\-](\d{1,2})[\/.\-]\d{2,4}/.exec(parsed.rows[r][c.index] || ""); if (m && +m[2] > 12) { us[c.index] = 1; break; } if (m && +m[1] > 12) break; } });
      var fix = function (c, v) { return us[c.index] && v ? v.replace(/^(\d{1,2})([\/.\-])(\d{1,2})\2/, "$3$2$1$2") : v; };
      var stageCols = cols.filter(function (c) { return c.field === "stage_entered"; });
      var deals = parsed.rows.map(function (r) {
        var d = { entered: stageCols.map(function (c) { return parseDate(fix(c, r[c.index])); }) };
        cols.forEach(function (c) { if (!c.field || c.field === "stage_entered") return; var v = r[c.index]; d[c.field] = c.pii ? (v ? cache[v] : "") : fix(c, v); });
        return d;
      });
      return { deals: deals, vault: vault, hashedValues: hashed, uniqueHashed: jobs.length, piiColumns: piiCols.map(function (c) { return c.source; }), stageNames: stageCols.map(function (c) { return c.stage; }) };
    });
  }

  // ---------- 4. deterministic analysis ----------
  function med(a) { if (!a.length) return null; var s = a.slice().sort(function (x, y) { return x - y; }), m = s.length >> 1; return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2; }
  function sum(a, f) { var t = 0; for (var i = 0; i < a.length; i++) t += f ? f(a[i]) : a[i]; return t; }
  function pc(a, b) { return b ? a / b * 100 : null; }
  function groupBy(a, f) { var o = {}; a.forEach(function (x) { var k = f(x); (o[k] = o[k] || []).push(x); }); return o; }
  // lower-is-better thresholds: < a green, a..b orange, > b red
  function low(v, a, b) { return v == null ? "na" : v < a ? "g" : v <= b ? "o" : "r"; }

  function analyze(anon, cfg) {
    var S = anon.stageNames.length, level = S ? "N2" : "N1", snap = 0;
    // business rules (all optional; defaults = référentiel)
    cfg = cfg || {};
    var qs = cfg.qualStage != null ? +cfg.qualStage : 1, mult = +cfg.stagMult || 2, wrMin = cfg.wrMin != null ? +cfg.wrMin : 17, wrMax = cfg.wrMax != null ? +cfg.wrMax : 30, fixed = cfg.fixedAmounts || [], rc = cfg.reasons || {}, mx = String(mult).replace(".", ",") + "×";
    var deals = anon.deals.map(function (r) {
      var st = norm(r.status || ""), sg = norm(r.stage || "");
      var status = /won|gagn|sign/.test(st || sg) ? "won" : /lost|perdu|abandon/.test(st || sg) ? "lost" : "open";
      var d = { id: r.deal_id, stage: r.stage || "", status: status, created: parseDate(r.created_at), amount: parseAmount(r.amount), owner: r.owner_id || "", company: r.company_id || "", source: (r.source || "").trim(), segment: (r.segment || "").trim(), reason: (r.lost_reason || "").trim(), pipeline: (r.pipeline || "").trim(), entered: r.entered, hasClose: !!r.close_date, lastAct: parseDate(r.last_activity_at) };
      var cd = parseDate(r.close_date), ca = parseDate(r.closed_at);
      d.closed = status === "open" ? null : (ca || cd); d.close = cd;
      [d.created, d.closed, d.lastAct].concat(d.entered).forEach(function (v) { if (v && v > snap) snap = v; });
      return d;
    }).filter(function (d) { return d.created; });
    var pipes = groupBy(deals, function (d) { return d.pipeline || "—"; });
    // several pipelines in one export: analyse the largest one unless told otherwise ("*" = all together)
    var pipeNames = Object.keys(pipes).sort(function (a, b) { return pipes[b].length - pipes[a].length; }), pipeUsed = cfg.pipeline === "*" ? null : (cfg.pipeline && pipes[cfg.pipeline] ? cfg.pipeline : (pipeNames.length > 1 ? pipeNames[0] : null));
    if (pipeUsed) deals = pipes[pipeUsed];
    var distinct = function (key) { return Object.keys(groupBy(deals.filter(function (d) { return d[key]; }), function (d) { return d[key]; })); }, values = { source: distinct("source"), segment: distinct("segment") };
    var excl = cfg.exclude || [];
    if (excl.length) deals = deals.filter(function (d) { return !excl.some(function (x) { return norm(d[x.key]) === norm(x.value); }); });
    // keep only the stage columns the analysed deals actually went through
    var keep = []; for (var s0 = 0; s0 < S; s0++) if (deals.some(function (d) { return d.entered[s0]; })) keep.push(s0);
    var stageNames = keep.map(function (k) { return anon.stageNames[k]; }); S = keep.length; level = S ? "N2" : "N1";
    deals.forEach(function (d) { d.entered = keep.map(function (k) { return d.entered[k]; }); d.maxStage = -1; d.firstStage = -1; for (var i = 0; i < S; i++) if (d.entered[i]) { d.maxStage = i; if (d.firstStage < 0) d.firstStage = i; } });
    // stage display names: reuse the spelling found in the data when it matches a stage-entered column
    var spelled = {}; deals.forEach(function (d) { spelled[norm(d.stage)] = d.stage; });
    var stages = stageNames.map(function (s) { return spelled[norm(s)] || s.charAt(0).toUpperCase() + s.slice(1); });
    if (!S) stages = Object.keys(groupBy(deals.filter(function (d) { return d.status === "open"; }), function (d) { return d.stage; }));
    var stageIx = {}; stages.forEach(function (s, i) { stageIx[norm(s)] = i; });
    deals.forEach(function (d) { d.age = (snap - d.created) / DAY; d.cycle = d.closed ? (d.closed - d.created) / DAY : null; var k = stageIx[norm(d.stage)]; d.cur = d.status === "open" ? (k != null ? k : d.maxStage) : -1; });

    var open = deals.filter(function (d) { return d.status === "open"; }), won = deals.filter(function (d) { return d.status === "won"; }), lost = deals.filter(function (d) { return d.status === "lost"; });
    var amt = function (d) { return d.amount || 0; }, openEur = sum(open, amt);
    var mature = deals.filter(function (d) { return d.created <= snap - 120 * DAY; }), cohort = mature.length >= deals.length * 0.3 ? mature : deals;
    var reached = function (d, i) { return d.status === "won" || d.maxStage >= i; };
    var M = { level: level, snap: snap, stages: stages, checks: [], locked: [] };
    var add = function (id, label, status, value, thr, n, text, x) {
      var c = { id: id, fam: id[0], label: label, status: status, value: value, thr: thr, n: n, text: text, indicative: n != null && n < 30 };
      if (n != null && n < 10 && status !== "na") { c.status = "na"; c.value = "n" + NB + "=" + NB + n; c.text = label + " : échantillon insuffisant (n" + NB + "=" + NB + n + ")."; }
      for (var k in x || {}) c[k] = x[k]; M.checks.push(c); return c;
    };

    // --- funnel (K1, K12) on the creation cohort ---
    var cw = cohort.filter(function (d) { return d.status === "won"; }), cl = cohort.filter(function (d) { return d.status === "lost"; });
    var qual = cohort.filter(function (d) { return d.status !== "open" && (S < 2 || reached(d, Math.min(qs, S - 1))); });
    var k2 = pc(qual.filter(function (d) { return d.status === "won"; }).length, qual.length), k3 = pc(sum(qual.filter(function (d) { return d.status === "won"; }), amt), sum(qual, amt));
    var recentWon = won.filter(function (d) { return d.closed >= snap - 365 * DAY && d.cycle != null; }), k4 = med(recentWon.map(function (d) { return d.cycle; }));
    var basket = med(won.filter(amt).map(amt)) || 0;
    M.funnel = []; var k5 = [];
    for (var i = 0; i < S; i++) {
      var r = cohort.filter(function (d) { return reached(d, i); }).length, nx = i < S - 1 ? cohort.filter(function (d) { return reached(d, i + 1); }).length : cw.length;
      var lh = cl.filter(function (d) { return d.maxStage === i; });
      var dur = deals.map(function (d) { var e = d.entered[i], x = i < S - 1 ? d.entered[i + 1] : (d.status === "won" ? d.closed : null); return e && x && x >= e ? (x - e) / DAY : null; }).filter(function (v) { return v != null; });
      k5[i] = dur.length >= 8 ? med(dur) : null;
      M.funnel.push({ name: stages[i], reached: r, next: nx, conv: pc(nx, r), days: k5[i], lost: lh.length, lostEur: sum(lh, amt) });
    }
    var downFrom = function (i) { var pr = 1; for (var z = i + 1; z < S; z++) pr *= (M.funnel[z].conv || 0) / 100; return pr; };
    M.kpi = { k2: k2, k2n: qual.length, k3: k3, k4: k4, k4n: recentWon.length, basket: basket, openEur: openEur };

    // --- A structure ---
    add("A1", "Nombre d’étapes", S ? (S >= 4 && S <= 7 ? "g" : S === 3 || S === 8 ? "o" : "r") : "na", S + " étapes", "4–7 vert · 3 ou 8 orange", null, "Le pipeline compte " + S + " étapes ouvertes.");
    var byCur = groupBy(open.filter(function (d) { return d.cur >= 0; }), function (d) { return d.cur; }), parkIx = Object.keys(byCur).sort(function (a, b) { return byCur[b].length - byCur[a].length; })[0];
    var park = parkIx != null ? pc(byCur[parkIx].length, open.length) : null;
    add("A2", "Étape fourre-tout", park == null ? "na" : park > 40 ? "r" : "g", park == null ? "—" : fmt.pct(park), "> 40 % des deals ouverts = rouge", open.length, park == null ? "" : fmt.pct(park) + " des deals ouverts sont en " + stages[parkIx] + ".");
    if (S) {
      var closedN2 = deals.filter(function (d) { return d.status !== "open" && d.maxStage >= 0; });
      var skipped = closedN2.filter(function (d) { var top = d.status === "won" ? S - 1 : d.maxStage; for (var j = d.firstStage; j <= top; j++) if (!d.entered[j]) return true; return false; });
      var a3 = pc(skipped.length, closedN2.length);
      add("A3", "Étapes sautées", low(a3, 10, 30), fmt.pct(a3), "< 10 % · 10–30 % · > 30 %", closedN2.length, fmt.pct(a3) + " des deals clos ont sauté au moins une étape.");
      var a4 = M.funnel.filter(function (f) { return f.conv > 95 && f.reached >= 30; })[0];
      add("A4", "Étape à conversion quasi totale", a4 ? "o" : "g", a4 ? fmt.pct(a4.conv) : "aucune", "> 95 % = orange", cohort.length, a4 ? "L’étape " + a4.name + " laisse passer " + fmt.pct(a4.conv) + " des deals : ce n’est pas un filtre." : "Chaque étape filtre réellement.");
      var late = deals.filter(function (d) { return d.firstStage > 0; }), a6 = pc(late.length, deals.filter(function (d) { return d.firstStage >= 0; }).length);
      add("A6", "Deals créés en étape avancée", low(a6, 10, 25), fmt.pct(a6), "< 10 % · 10–25 % · > 25 %", deals.length, fmt.pct(a6) + " des deals apparaissent directement en étape avancée.", { reco: "Créer le deal au premier contact qualifié ; automatiser la création depuis les formulaires.", horizon: "quick", group: 1 });
    }

    // --- B conversion ---
    var wrRed = Math.max(10, wrMin / 2), wrTxt = "la fourchette attendue de " + wrMin + " à " + wrMax + NB + "%";
    add("B2", "Win rate vs fourchette attendue", k2 == null ? "na" : k2 >= wrMin ? "g" : k2 >= wrRed ? "o" : "r", k2 == null ? "—" : fmt.pct(k2), wrMin + "–" + wrMax + " % attendu · < " + Math.round(wrRed) + " % rouge", qual.length, k2 == null ? "" : "Win rate de " + fmt.pct(k2) + " sur les deals qualifiés, " + (k2 >= wrMin ? (k2 > wrMax ? "au-dessus de " : "dans ") : "sous ") + wrTxt + ".", { cause: "Qualification trop permissive à l’entrée, ou ciblage hors de la clientèle idéale.", reco: "Ne pas travailler le closing : durcir la qualification à l’entrée du funnel.", group: 3 });
    var b3 = k2 != null && k3 != null ? k2 - k3 : null;
    add("B3", "Win rate en montant vs en nombre", low(b3, 10, 20), b3 == null ? "—" : (b3 >= 0 ? "−" : "+") + Math.abs(b3).toFixed(1).replace(".", ",") + NB + "pts", "écart > 10 pts orange · > 20 rouge", qual.length, b3 == null ? "" : "Win rate de " + fmt.pct(k3) + " en montant contre " + fmt.pct(k2) + " en nombre.", { reco: "Revue des dix plus gros deals perdus ; process dédié au-dessus d’un seuil de montant.", group: 3 });
    var wk = function (d) { return Math.floor((snap - d.created) / (7 * DAY)); }, last4 = deals.filter(function (d) { return wk(d) < 4; }).length / 4, prev12 = deals.filter(function (d) { var w = wk(d); return w >= 4 && w < 16; }).length / 12;
    var b4 = prev12 ? (last4 - prev12) / prev12 * 100 : null;
    add("B4", "Création de pipeline", b4 == null ? "na" : b4 < -20 ? "o" : "g", b4 == null ? "—" : (b4 >= 0 ? "+" : "−") + Math.abs(Math.round(b4)) + NB + "%", "baisse > 20 % sur 4 semaines = orange", Math.round(prev12 * 12), b4 == null ? "" : b4 < -20 ? "La création de pipeline recule de " + Math.abs(Math.round(b4)) + NB + "% sur quatre semaines." : "La création de pipeline tient : " + Math.round(last4) + " deals par semaine sur les quatre dernières.", { reco: "Objectif de création hebdomadaire par commercial ; cadence de prospection protégée.", group: 4, chart: "monthly" });
    var seg = function (key) {
      var g = groupBy(qual.filter(function (d) { return d[key]; }), function (d) { return d[key]; }), tot = cohort.filter(function (d) { return d[key]; }).length;
      return Object.keys(g).map(function (k) { var a = g[k], w = a.filter(function (d) { return d.status === "won"; }); return { name: k, n: a.length, wr: pc(w.length, a.length), vol: pc(cohort.filter(function (d) { return d[key] === k; }).length, tot), cycle: med(w.filter(function (d) { return d.cycle != null; }).map(function (d) { return d.cycle; })) }; }).filter(function (x) { return x.n >= 10; }).sort(function (a, b) { return b.wr - a.wr; });
    };
    var mix = function (id, label, key, word, none) {
      var list = seg(key); M[key + "s"] = list; if (list.length < 2) return add(id, label, "na", "—", "", null, "");
      var best = list[0], weak = list.filter(function (x) { return x.n >= 30 && x.vol > 20 && x.wr < best.wr / 2; })[0];
      add(id, label, weak ? "r" : "g", weak ? fmt.pct(weak.wr) + " vs " + fmt.pct(best.wr) : fmt.pct(list[list.length - 1].wr) + " à " + fmt.pct(best.wr), "> 20 % du volume et win rate < moitié du meilleur = rouge", sum(list, function (x) { return x.n; }), weak ? word + " « " + weak.name + " » pèse " + fmt.pct(weak.vol) + " du volume et convertit à " + fmt.pct(weak.wr) + ", contre " + fmt.pct(best.wr) + " pour « " + best.name + " »." : none + " ne décroche : de " + fmt.pct(list[list.length - 1].wr) + " à " + fmt.pct(best.wr) + " de win rate.", { reco: "Durcir la qualification à l’entrée pour « " + (weak ? weak.name : "") + " » ou réallouer l’effort.", group: 3, chart: key });
    };
    mix("B5", "Conversion par source", "source", "La source", "Aucune source"); mix("I1", "Performance par segment", "segment", "Le segment", "Aucun segment");
    if (S >= 4) {
      var lateL = cl.filter(function (d) { return d.maxStage >= S - 2; }), earlyL = cl.filter(function (d) { return d.maxStage <= 1; }), b6 = pc(lateL.length, cl.length), g2 = pc(earlyL.length, cl.length);
      add("B6", "Pertes en fin de funnel", b6 == null ? "na" : b6 > 50 ? "r" : "g", fmt.pct(b6), "> 50 % des pertes aux deux dernières étapes = rouge", cl.length, fmt.pct(b6) + " des pertes surviennent en " + stages[S - 2] + " ou en " + stages[S - 1] + ".", { detail: fmt.int(lateL.length) + " deals perdus après le chiffrage, soit " + fmt.eur(sum(lateL, amt)) + ".", impact: sum(lateL, amt), cause: "Les deals avancent sans être qualifiés : décideur jamais rencontré, pas d’échéance côté client.", potential: (function () { var li = M.funnel[S - 2].conv < M.funnel[S - 1].conv ? S - 2 : S - 1, gain = 0.10 * M.funnel[li].reached * downFrom(li); return "Dix points de conversion de plus en " + M.funnel[li].name + " : environ " + Math.round(gain) + " deals gagnés de plus sur la cohorte, soit " + fmt.eur(gain * basket) + "."; })(), reco: "Critères de sortie en découverte (décideur, budget, échéance) ; pas de proposition sans décideur identifié.", group: 3, chart: "loss", absorbs: ["G2"] });
      add("G2", "Disqualification précoce", g2 == null ? "na" : g2 > 40 ? "g" : g2 >= 20 ? "o" : "r", fmt.pct(g2), "> 40 % des pertes tôt = vert · < 20 % rouge", cl.length, "Seulement " + fmt.pct(g2) + " des pertes arrivent aux deux premières étapes.", { reco: "Critères de disqualification explicites ; valoriser la perte précoce en revue.", group: 3, chart: "loss" });
      var worst = M.funnel.slice().sort(function (a, b) { return b.lostEur - a.lostEur; })[0], lostTot = sum(M.funnel, function (f) { return f.lostEur; }), b1 = worst && pc(worst.lostEur, lostTot);
      M.leak = worst && b1 > 30 && worst.conv < 60 ? worst.name : null;
      add("B1", "Fuite à une étape", M.leak ? "r" : "g", worst ? fmt.pct(worst.conv) : "—", "conversion faible et > 30 % des € perdus = rouge", worst ? worst.reached : null, M.leak ? "L’étape " + worst.name + " ne laisse passer que " + fmt.pct(worst.conv) + " des deals et concentre " + fmt.pct(b1) + " des montants perdus." : "Aucune étape ne concentre les pertes.", { reco: "Traiter la compétence de l’étape " + (worst ? worst.name : "") + " : business case, accès au décideur, plan d’action mutuel.", group: 3, chart: "funnel", impact: worst ? worst.lostEur : 0, absorbedBy: "B6" });
    }

    // --- C velocity ---
    var autoDays = basket < 1e4 ? 60 : basket < 25e3 ? 90 : basket < 5e4 ? 120 : basket < 1e5 ? 180 : 270, alertDays = +cfg.cycle || autoDays;
    add("C1", "Cycle de vente vs attendu", k4 == null ? "na" : k4 <= alertDays ? "g" : k4 <= alertDays * 1.5 ? "o" : "r", k4 == null ? "—" : fmt.days(k4), (cfg.cycle ? "cycle attendu déclaré : " : "zone d’alerte pour ce panier : ") + alertDays + " j", recentWon.length, k4 == null ? "" : "Cycle médian de " + fmt.days(k4) + " pour un panier médian de " + fmt.eur(basket) + (k4 <= alertDays ? " : cohérent." : " : au-delà " + (cfg.cycle ? "du cycle attendu (" : "de la zone d’alerte (") + alertDays + NB + "j)."), { cause: "Une étape goulot, ou des deals non qualifiés qui traînent.", reco: "Identifier l’étape goulot avant toute action sur le closing.", group: 4, chart: "time" });
    var stag = [], c3 = null, c4 = null;
    if (S) {
      var tot5 = sum(k5.filter(Boolean)), bott = k5.map(function (v, i) { return { i: i, sh: v ? v / tot5 * 100 : 0 }; }).sort(function (a, b) { return b.sh - a.sh; })[0];
      add("C2", "Étape goulot", low(bott.sh, 30, 40), fmt.pct(bott.sh), "> 30 % du cycle orange · > 40 % rouge", recentWon.length, "L’étape " + stages[bott.i] + " consomme " + fmt.pct(bott.sh) + " du cycle.", { reco: "Rendre visible la dépendance externe de l’étape " + stages[bott.i] + " et l’anticiper.", group: 4, chart: "time" });
      stag = open.filter(function (d) { return d.cur >= 0 && d.entered[d.cur] && k5[d.cur] && (snap - d.entered[d.cur]) / DAY > mult * k5[d.cur]; });
      c3 = pc(sum(stag, amt), openEur);
      add("C3", "Deals stagnants", low(c3, 15, 30), fmt.pct(c3), "< 15 % · 15–30 % · > 30 % du pipeline en €", open.length, fmt.pct(c3) + " du pipeline ouvert stagne : " + stag.length + " deals sans mouvement depuis plus de " + mx + " la durée médiane de leur étape.", { impact: sum(stag, amt), reco: "Règle automatique « sans mouvement depuis " + mx + " la médiane de l’étape → à requalifier ».", horizon: "quick", group: 2, chart: "pipe" });
    }
    if (k4) { var old = open.filter(function (d) { return d.age > 2 * k4; }); c4 = pc(old.length, open.length); add("C4", "Âge du pipeline ouvert", low(c4, 10, 25), fmt.pct(c4), "< 10 % · 10–25 % · > 25 %", open.length, fmt.pct(c4) + " des deals ouverts ont plus de deux fois l’âge d’un cycle gagnant (" + fmt.days(2 * k4) + ").", { reco: "Purger ou requalifier ; ces deals ne comptent pas dans la couverture.", horizon: "quick", group: 4, chart: "age" }); }
    if (!S && k4) { stag = open.filter(function (d) { return d.age > mult * k4; }); c3 = pc(sum(stag, amt), openEur); add("C3", "Deals stagnants (approché par l’âge)", low(c3, 15, 30), fmt.pct(c3), "< 15 % · 15–30 % · > 30 % du pipeline en €", open.length, fmt.pct(c3) + " du pipeline ouvert a plus de " + mx + " l’âge d’un cycle gagnant : " + stag.length + " deals.", { impact: sum(stag, amt), reco: "Requalifier ou fermer ces deals ; règle de purge automatique.", horizon: "quick", group: 2, chart: "pipe" }); }

    // --- D data hygiene ---
    var miss = [["amount", "montant", function (d) { return d.amount == null; }], ["close_date", "close date", function (d) { return !d.hasClose; }], ["owner", "commercial", function (d) { return !d.owner; }], ["source", "source", function (d) { return !d.source; }]].map(function (f) { return { key: f[0], label: f[1], miss: pc(open.filter(f[2]).length, open.length) || 0 }; });
    M.completeness = miss; var d1 = miss.slice().sort(function (a, b) { return b.miss - a.miss; })[0];
    add("D1", "Champs clés vides", low(d1.miss, 5, 15), fmt.pct(d1.miss, 1), "< 5 % · 5–15 % · > 15 % par champ", open.length, d1.miss < 5 ? "Les champs clés sont renseignés : au plus " + fmt.pct(d1.miss, 1) + " de vides (" + d1.label + ")." : fmt.pct(d1.miss) + " des deals ouverts n’ont pas de " + d1.label + ".", { reco: "Rendre montant et close date obligatoires dès le stade qualifié.", horizon: "quick", group: 1 });
    var past = open.filter(function (d) { return d.close && d.close < snap; }), d2 = pc(past.length, open.length);
    add("D2", "Close date dépassée", low(d2, 5, 15), fmt.pct(d2), "< 5 % · 5–15 % · > 15 % des deals ouverts", open.length, fmt.pct(d2) + " des deals ouverts ont une close date déjà passée (" + fmt.eur(sum(past, amt)) + ").", { impact: sum(past, amt), reco: "Alerte automatique à J−7 ; close date passée interdite par workflow.", horizon: "quick", group: 1, chart: "close" });
    if (deals.some(function (d) { return d.lastAct; })) { var idleDays = basket < 1e4 ? 14 : 30, idle = open.filter(function (d) { return !d.lastAct || (snap - d.lastAct) / DAY > idleDays; }), d5 = pc(idle.length, open.length); add("D5", "Deals sans activité", low(d5, 15, 30), fmt.pct(d5), "< 15 % · 15–30 % · > 30 % des deals ouverts", open.length, fmt.pct(d5) + " des deals ouverts n’ont eu aucune activité depuis " + idleDays + " jours (" + fmt.eur(sum(idle, amt)) + ").", { cause: "Activités non enregistrées dans le CRM, ou deals abandonnés sans être fermés.", impact: sum(idle, amt), reco: "Vérifier d’abord l’enregistrement des activités (e-mail et agenda reliés au CRM) ; puis fermeture automatique après 60 jours sans activité.", horizon: "quick", group: 4.5 }); }
    var withAmt = deals.filter(function (d) { return d.amount > 0; }), freq = groupBy(withAmt.filter(function (d) { return fixed.indexOf(d.amount) < 0; }), function (d) { return d.amount; }), modeV = Object.keys(freq).sort(function (a, b) { return freq[b].length - freq[a].length; })[0], d6 = modeV ? pc(freq[modeV].length, withAmt.length) : null;
    var freqAll = groupBy(withAmt, function (d) { return d.amount; }), modeAll = Object.keys(freqAll).sort(function (a, b) { return freqAll[b].length - freqAll[a].length; })[0], modeAllShare = modeAll ? pc(freqAll[modeAll].length, withAmt.length) : 0;
    var phOpen = open.filter(function (d) { return d.amount === +modeV; });
    add("D6", "Montants par défaut", d6 == null ? "na" : d6 > 30 ? "r" : d6 >= 10 ? "o" : "g", fmt.pct(d6), "> 30 % sur une même valeur = rouge", withAmt.length, fmt.pct(d6) + " des deals portent exactement le même montant : " + fmt.int(+modeV) + NB + "€.", { detail: "Une valeur par défaut, pas une estimation : " + fmt.eur(sum(phOpen, amt)) + " du pipeline ouvert reposent dessus.", impact: sum(phOpen, amt), cause: "Valeur par défaut du CRM, ou montant saisi seulement au moment du closing.", reco: "Montant estimé obligatoire dès la qualification ; valeur par défaut interdite.", horizon: "quick", group: 4.5, chart: "amounts", mode: +modeV });
    var comp = groupBy(open.filter(function (d) { return d.company; }), function (d) { return d.company; }), compK = Object.keys(comp), d7 = pc(compK.filter(function (k) { return comp[k].length > 1; }).length, compK.length);
    add("D7", "Doublons par entreprise", low(d7, 3, 10), d7 == null ? "—" : fmt.pct(d7, 1), "< 3 % · 3–10 % · > 10 %", compK.length, d7 == null ? "" : fmt.pct(d7, 1) + " des entreprises ont plusieurs deals ouverts.", { reco: "Règle d’unicité et attribution de compte.", horizon: "quick", group: 4.5 });
    var defClass = function (name) { var n = norm(name); return !n || /^(vide|autre|autres|other|sans suite|n a|na|inconnu|unknown|divers)$/.test(n) ? "vague" : /(budget|report|no decision|sans decision|statu quo|abandon|timing|plus de besoin|pas de besoin|silence|sans reponse)/.test(n) ? "nd" : /(concurr|competit)/.test(n) ? "comp" : /(prix|price|tarif|cher)/.test(n) ? "price" : "other"; }, classOf = function (name) { return rc[name] || defClass(name); };
    var reasons = groupBy(lost, function (d) { return d.reason || "(vide)"; });
    M.reasons = Object.keys(reasons).map(function (k) { return { name: k, n: reasons[k].length, eur: sum(reasons[k], amt), cls: classOf(k) }; }).sort(function (a, b) { return b.n - a.n; });
    var rs = function (c) { return M.reasons.filter(function (x) { return x.cls === c; }); }, rn = function (a) { return sum(a, function (x) { return x.n; }); }, re = function (a) { return sum(a, function (x) { return x.eur; }); };
    var vagueR = rs("vague"), ndR = rs("nd"), vague = pc(rn(vagueR), lost.length), usable = lost.length - rn(vagueR), g4 = pc(rn(ndR), usable);
    add("D8", "Raisons de perte inexploitables", vague == null ? "na" : vague > 40 ? "r" : "g", fmt.pct(vague), "> 40 % vides ou fourre-tout = rouge", lost.length, vague > 40 ? fmt.pct(vague) + " des raisons de perte ne disent rien : " + vagueR.map(function (x) { return x.name === "(vide)" ? "champ vide" : "« " + x.name + " »"; }).join(", ") + "." : "Les raisons de perte sont exploitables : " + fmt.pct(vague) + " de valeurs vides ou fourre-tout.", { detail: "C’est d’abord un problème de saisie : tant que la raison est un fourre-tout, impossible de savoir contre quoi vous perdez." + (g4 != null ? " Parmi les raisons exploitables, " + fmt.pct(g4) + " sont des pertes sans décision de l’acheteur." : ""), cause: "Liste de raisons trop vague et champ non contrôlé : le commercial choisit la valeur la plus rapide à saisir.", impact: re(vagueR), reco: "Six à huit raisons précises, obligatoires à la perte ; supprimer les valeurs fourre-tout ; distinguer « sans décision » de « concurrent ».", horizon: "quick", group: 3, chart: "reasons", absorbs: ["G4"] });

    // --- G method ---
    add("G4", "Pertes sans décision", low(g4, 30, 50), fmt.pct(g4), "< 30 % · 30–50 % · > 50 % des raisons exploitables", usable, fmt.pct(g4) + " des pertes renseignées sont sans décision de l’acheteur.", { detail: "On perd contre le statu quo, pas contre un concurrent : " + fmt.eur(re(ndR)) + " concernés.", cause: "Valeur ou urgence non établies ; aucun événement déclencheur côté client.", impact: re(ndR), reco: "Question « pourquoi maintenant ? » obligatoire en découverte ; business case chiffré avant la proposition.", group: 3, chart: "reasons" });
    var fast = won.filter(function (d) { return d.cycle != null && d.cycle < 7; }), g6 = pc(fast.length, won.length);
    add("G6", "Deals gagnés sans parcours", low(g6, 10, 25), fmt.pct(g6, 1), "< 10 % · 10–25 % · > 25 %", won.length, fmt.pct(g6, 1) + " des deals gagnés le sont en moins de sept jours.", { reco: "Isoler l’inbound chaud dans un segment dédié ; vérifier la saisie a posteriori.", group: 4.5 });

    // --- H forecast discipline ---
    var eom = function (t) { return new Date(t + DAY).getUTCDate() === 1; }, withClose = open.filter(function (d) { return d.close; }), h3 = pc(withClose.filter(function (d) { return eom(d.close); }).length, withClose.length);
    add("H3", "Close dates en fin de mois", cfg.eomOk ? (h3 == null ? "na" : "g") : low(h3, 20, 40), fmt.pct(h3), "< 20 % · 20–40 % · > 40 %", withClose.length, fmt.pct(h3) + " des close dates tombent le dernier jour du mois" + (cfg.eomOk ? ", ce qui correspond à votre règle de démarrage ou de facturation." : "."), { reco: "Une close date = un événement côté client ; sinon « à qualifier ».", horizon: "quick", group: 4, chart: "close" });
    var last5 = function (t) { var d = new Date(t), n = 0, x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)); while (x.getTime() > t) { var w = x.getUTCDay(); if (w && w < 6) n++; x = new Date(x.getTime() - DAY); } return n < 5; };
    var h2 = pc(won.filter(function (d) { return d.closed && last5(d.closed); }).length, won.length);
    add("H2", "Hockey stick", low(h2, 35, 50), fmt.pct(h2), "< 35 % · 35–50 % · > 50 %", won.length, fmt.pct(h2) + " des deals gagnés se signent dans les cinq derniers jours ouvrés du mois.", { reco: "Découpler la politique de remise du calendrier.", group: 4 });

    // --- E people (always phrased by stage and skill, never by name) ---
    var owners = groupBy(deals.filter(function (d) { return d.owner; }), function (d) { return d.owner; }), codes = Object.keys(owners).sort(function (a, b) { return owners[b].length - owners[a].length; });
    M.reps = codes.map(function (h, i) {
      var q = qual.filter(function (d) { return d.owner === h; }), w = owners[h].filter(function (d) { return d.status === "won"; });
      return { hash: h, code: "Commercial " + String.fromCharCode(65 + i % 26), closed: q.length, wr: q.length >= 15 ? pc(q.filter(function (d) { return d.status === "won"; }).length, q.length) : null, wonEur: sum(w, amt), open: owners[h].filter(function (d) { return d.status === "open"; }).length,
        stageConv: M.funnel.map(function (f, s) { var a = cohort.filter(function (d) { return d.owner === h && reached(d, s); }), b = s < S - 1 ? a.filter(function (d) { return reached(d, s + 1); }) : a.filter(function (d) { return d.status === "won"; }); return a.length >= 15 ? { n: a.length, conv: pc(b.length, a.length) } : null; }) };
    });
    var cmp = M.reps.filter(function (r) { return r.wr != null; });
    if (cmp.length >= 4) {
      var mean = sum(cmp, function (r) { return r.wr; }) / cmp.length, cv = Math.sqrt(sum(cmp, function (r) { return Math.pow(r.wr - mean, 2); }) / cmp.length) / mean;
      add("E1", "Dispersion du win rate", low(cv, 0.25, 0.45), cv.toFixed(2).replace(".", ","), "CV < 0,25 · 0,25–0,45 · > 0,45", sum(cmp, function (r) { return r.closed; }), cv < 0.25 ? "La méthode est partagée : le win rate varie peu d’un commercial à l’autre (CV " + cv.toFixed(2).replace(".", ",") + ")." : "Le win rate varie fortement d’un commercial à l’autre (CV " + cv.toFixed(2).replace(".", ",") + ").", { reco: "Formaliser en playbook ce que font les meilleurs (écoute d’appels).", group: 5, chart: "reps" });
      var top = M.reps.slice().sort(function (a, b) { return b.wonEur - a.wonEur; }).slice(0, Math.max(1, Math.ceil(M.reps.length * 0.2))), e4 = pc(sum(top, function (r) { return r.wonEur; }), sum(M.reps, function (r) { return r.wonEur; }));
      add("E4", "Concentration de la performance", low(e4, 40, 60), fmt.pct(e4), "< 40 % · 40–60 % · > 60 %", sum(cmp, function (r) { return r.closed; }), fmt.pct(e4) + " du montant gagné vient de " + top.length + " commerciaux sur " + M.reps.length + ".", { reco: "Documenter la méthode des meilleurs ; vérifier l’équité des territoires.", group: 5, chart: "reps" });
      var flags = [];
      M.reps.forEach(function (r) { r.stageConv.forEach(function (c, s) { if (c && M.funnel[s].conv && c.conv < 0.7 * M.funnel[s].conv) flags.push({ rep: r, s: s, conv: c.conv, n: c.n, team: M.funnel[s].conv }); }); });
      flags = flags.filter(function (f) { return flags.filter(function (g) { return g.s === f.s; }).length <= cmp.length / 2; }).sort(function (a, b) { return a.conv / a.team - b.conv / b.team; });
      var e2 = flags[0]; M.blocked = e2 ? { hash: e2.rep.hash, stage: e2.s } : null;
      add("E2", "Blocage individuel à une étape", !S ? "na" : e2 ? "r" : "g", e2 ? fmt.pct(e2.conv) + " vs " + fmt.pct(e2.team) : "aucun", "conversion < 0,7× l’équipe sur une étape = rouge", e2 ? e2.n : sum(cmp, function (r) { return r.closed; }), e2 ? "Un commercial convertit " + fmt.pct(e2.conv) + " de ses deals en " + stages[e2.s] + ", contre " + fmt.pct(e2.team) + " pour l’équipe." : "Aucun commercial ne décroche de l’équipe sur une étape précise.", { detail: e2 ? "Écart mesuré sur " + e2.n + " deals arrivés à cette étape. L’équipe est dans la norme : c’est une compétence précise, pas un problème collectif." : "", impact: e2 ? (e2.team - e2.conv) / 100 * e2.n * downFrom(e2.s) * basket : 0, cause: "Une compétence propre à cette étape (chiffrage, business case, accès au décideur), pas la méthode collective.", potential: e2 ? "Au niveau de l’équipe, ce commercial gagnerait environ " + Math.round((e2.team - e2.conv) / 100 * e2.n * downFrom(e2.s)) + " deals de plus sur la cohorte." : "", reco: e2 ? "Co-écoute des rendez-vous de l’étape " + stages[e2.s] + " et objectif de conversion à 30 jours." : "", group: 5, chart: "reps" });
    }

    // --- pattern P1: stagnant ∪ outdated pipeline (absorbs C3, D2, H3, C4) ---
    var byId = {}; M.checks.forEach(function (c) { byId[c.id] = c; });
    var uni = open.filter(function (d) { return stag.indexOf(d) >= 0 || (d.close && d.close < snap); }), both = stag.filter(function (d) { return d.close && d.close < snap; });
    M.pipe = { open: openEur, n: open.length, stagOnly: sum(stag, amt) - sum(both, amt), both: sum(both, amt), pastOnly: sum(past, amt) - sum(both, amt), union: sum(uni, amt), unionN: uni.length };
    var isBad = function (id) { return byId[id] && (byId[id].status === "o" || byId[id].status === "r"); };
    if (isBad("C3") && isBad("D2")) {
      var p1 = pc(M.pipe.union, openEur);
      M.checks.push({ id: "P1", fam: "P", pattern: true, label: "Pipeline fictif", status: "r", critical: true, value: fmt.pct(p1), n: open.length, thr: "C3 et D2 hors du vert", text: fmt.pct(p1) + " du pipeline ouvert est inactif ou périmé.", detail: uni.length + " deals stagnants ou à close date dépassée : " + fmt.eur(M.pipe.union) + " sur " + fmt.eur(openEur) + " ouverts. La couverture réelle est plus basse qu’elle n’en a l’air.", impact: M.pipe.union, cause: "Aucune règle de purge : les deals restent ouverts pour tenir la couverture, et la revue juge le volume plutôt que le mouvement.", reco: "Requalifier ou fermer ces " + uni.length + " deals, puis activer la règle « sans mouvement depuis " + mx + " la médiane de l’étape → à requalifier ».", horizon: "quick", group: 2, chart: "pipe", absorbs: ["C3", "D2", "H3", "C4", "D5"] });
    }

    // --- findings: hierarchy of référentiel §8, absorbed symptoms removed ---
    var absorbed = {}; M.checks.forEach(function (c) { if ((c.status === "r" || c.status === "o") && c.absorbs) c.absorbs.forEach(function (a) { absorbed[a] = c.id; }); });
    if (isBad("B6")) absorbed.B1 = "B6";
    var rank = { r: 0, o: 1 };
    M.findings = M.checks.filter(function (c) { return (c.status === "r" || c.status === "o") && !absorbed[c.id] && c.group; }).sort(function (a, b) { return a.group - b.group || rank[a.status] - rank[b.status] || (b.impact || 0) - (a.impact || 0); });
    M.top = M.findings.filter(function (c) { return c.status === "r" || c.impact; }).slice(0, 5); M.others = M.findings.filter(function (c) { return M.top.indexOf(c) < 0; });
    M.good = ["B2", "E1", "D1", "A3", "E4", "H2", "B4", "D8"].map(function (id) { return byId[id]; }).filter(function (c) { return c && c.status === "g"; }).slice(0, 3);
    M.absorbed = absorbed;
    [["D3", "Slippage des close dates", "N3"], ["D4", "Mises à jour en rafale", "N3"], ["E7", "Slippage par commercial", "N3"], ["F3", "Changements d’owner", "N3"], ["H1", "Fiabilité du forecast", "N3"], ["H4", "Sandbagging", "N3"], ["D5", "Deals sans activité", "N4"], ["E5", "Commerciaux en ramp", "N4"], ["E6", "Couverture par commercial", "N4"], ["F1", "Handoff SDR → AE", "N4"], ["F2", "Délai de prise en charge", "N4"], ["G1", "Critères de sortie", "Contexte"], ["G3", "Qualification de façade", "Contexte"]]
      .forEach(function (l) { if (byId[l[0]]) return; M.locked.push({ id: l[0], fam: l[0][0], label: l[1], needs: l[2], status: "lock", text: l[2] === "N3" ? "Se débloque avec un export déposé chaque semaine." : l[2] === "N4" ? "Se débloque avec les activités, les quotas et les rôles." : "Se débloque avec trois questions après ce rapport." }); });

    // --- chart series ---
    var bins = []; for (var b = 0; b < 9; b++) bins.push({ from: b * 30, n: 0, eur: 0 });
    open.forEach(function (d) { var k = Math.min(8, Math.floor(d.age / 30)); bins[k].n++; bins[k].eur += amt(d); }); M.ageBins = bins;
    var mKey = function (t) { var d = new Date(t); return d.getUTCFullYear() * 12 + d.getUTCMonth(); }, sm = mKey(snap), ML = ["J", "F", "M", "A", "M", "J", "J", "A", "S", "O", "N", "D"];
    M.closeMonths = []; for (var k = sm - 5; k <= sm + 6; k++) (function (k) { var a = withClose.filter(function (d) { return mKey(d.close) === k; }); M.closeMonths.push({ label: ML[k % 12], past: a.filter(function (d) { return d.close < snap; }).length, future: a.filter(function (d) { return d.close >= snap; }).length, eom: a.filter(function (d) { return eom(d.close); }).length, current: k === sm }); })(k);
    M.monthly = []; for (var m2 = sm - 14; m2 <= sm; m2++) (function (k) { M.monthly.push({ label: ML[k % 12], created: deals.filter(function (d) { return mKey(d.created) === k; }).length, won: won.filter(function (d) { return d.closed && mKey(d.closed) === k; }).length, partial: k === sm }); })(m2);
    M.amountBins = []; for (var a2 = 0; a2 <= 30; a2++) M.amountBins.push({ k: a2, n: 0 });
    withAmt.forEach(function (d) { M.amountBins[Math.min(30, Math.floor(d.amount / 1000))].n++; });
    M.openStages = stages.map(function (st, i) { var a = open.filter(function (d) { return d.cur === i; }); return { name: st, n: a.length, eur: sum(a, amt) }; });
    // questions asked from what this very file contains (answers set business rules)
    var Q = [];
    if (pipeNames.length > 1) Q.push({ id: "pipeline", check: "A5", text: "Votre export contient " + pipeNames.length + " pipelines. Lequel faut-il analyser ?", why: "Mélanger deux pipelines fausse toutes les moyennes. Par défaut, le plus volumineux est analysé.", options: pipeNames.slice(0, 3).map(function (pn) { return { label: pn + " · " + pipes[pn].length + " deals", set: { pipeline: pn } }; }).concat([{ label: "Tous ensemble", set: { pipeline: "*" } }]) });
    M.reasons.forEach(function (x) { var sh = pc(x.n, lost.length); if (x.name !== "(vide)" && defClass(x.name) === "vague" && sh >= 10) { var a = { reasons: {} }, b = { reasons: {} }; a.reasons[x.name] = "nd"; b.reasons[x.name] = "vague"; Q.push({ id: "reason:" + x.name, check: "D8", text: fmt.pct(sh) + " de vos pertes sont classées « " + x.name + " ». Chez vous, que veut dire cette valeur ?", why: "Selon la réponse, c’est un problème de saisie ou une vraie perte sans décision de l’acheteur.", options: [{ label: "Le prospect ne donne plus suite", set: a }, { label: "Une case par défaut, on ne sait pas", set: b }] }); } });
    if (modeAllShare >= 10) Q.push({ id: "fixed", check: "D6", text: fmt.pct(modeAllShare) + " de vos deals sont à exactement " + fmt.int(+modeAll) + NB + "€. Est-ce le prix d’une offre à prix fixe ?", why: "Si oui, ce montant est légitime. Sinon, c’est une valeur saisie par défaut.", options: [{ label: "Oui, un prix catalogue", set: { addFixed: +modeAll } }, { label: "Non, une valeur par défaut", set: { removeFixed: +modeAll } }] });
    if (h3 != null && h3 >= 20) Q.push({ id: "eom", check: "H3", text: fmt.pct(h3) + " de vos close dates tombent le dernier jour du mois. Est-ce une règle chez vous ?", why: "Un démarrage ou une facturation en début de mois l’explique. Sinon, ce sont des dates mises par défaut.", options: [{ label: "Oui, c’est voulu", set: { eomOk: true } }, { label: "Non, des dates par défaut", set: { eomOk: false } }] });
    if (k4 != null && k4 > 0.75 * autoDays) Q.push({ id: "cycle", check: "C1", text: "Votre cycle de vente médian est de " + fmt.days(k4) + ". Quel cycle visez-vous ?", why: "Sans réponse, la référence est celle de votre panier médian : " + autoDays + " jours.", options: [[30, "Un mois"], [60, "Deux mois"], [90, "Trois mois"], [180, "Six mois ou plus"]].map(function (o) { return { label: o[1], set: { cycle: o[0] } }; }) });
    if (k2 != null) Q.push({ id: "motion", check: "B2", text: "Votre win rate est de " + fmt.pct(k2) + ". D’où viennent surtout vos deals ?", why: "La fourchette attendue change : 30–45 % sur des demandes entrantes, 10–20 % en prospection à froid.", options: [{ label: "Demandes entrantes", set: { wrMin: 30, wrMax: 45 } }, { label: "Prospection à froid", set: { wrMin: 10, wrMax: 20 } }, { label: "Un mélange", set: { wrMin: 17, wrMax: 30 } }] });
    if (S >= 3) Q.push({ id: "qual", check: "B2", text: "À partir de quelle étape un deal est-il vraiment qualifié chez vous ?", why: "Le win rate se calcule sur les deals ayant atteint cette étape.", options: stages.slice(0, Math.min(4, S)).map(function (st, i) { return { label: st, set: { qualStage: i } }; }) });
    M.questions = Q; M.values = values;
    M.rules = { eomOk: !!cfg.eomOk, exclude: excl, qualStage: Math.min(qs, Math.max(S - 1, 0)), stagMult: mult, wrMin: wrMin, wrMax: wrMax, cycle: +cfg.cycle || null, cycleAuto: autoDays, fixedAmounts: fixed, pipeline: pipeUsed, pipelines: pipeNames.map(function (k) { return { name: k, n: pipes[k].length }; }) };
    // compact anonymised snapshot of the analysed pipeline, kept by the app to compare with the next export
    var idOk = deals.length && deals.every(function (d) { return d.id; }) && Object.keys(groupBy(deals, function (d) { return d.id; })).length === deals.length;
    M.snapshot = idOk ? { date: snap, stages: stages, deals: deals.map(function (d) { return [String(d.id), d.cur, d.status === "won" ? 1 : d.status === "lost" ? 2 : 0, d.amount || 0, d.close || 0, d.owner]; }) } : null;
    M.meta = { rows: deals.length, open: open.length, won: won.length, lost: lost.length, months: Math.round((snap - Math.min.apply(null, deals.map(function (d) { return d.created; }))) / DAY / 30.4), reps: codes.length, cohort: cohort.length, executed: M.checks.filter(function (c) { return c.status !== "na" && !c.pattern; }).length };
    return M;
  }

  // ---------- 5. business rules: apply a patch, read free text ----------
  var CLS = { vague: "valeur fourre-tout", nd: "sans décision de l’acheteur", comp: "concurrence", price: "prix", other: "autre motif précis" };
  function applyRule(cfg, set) {
    for (var k in set) {
      if (k === "reasons") { cfg.reasons = cfg.reasons || {}; for (var r in set.reasons) cfg.reasons[r] = set.reasons[r]; }
      else if (k === "addFixed") cfg.fixedAmounts = (cfg.fixedAmounts || []).filter(function (v) { return v !== set.addFixed; }).concat([set.addFixed]);
      else if (k === "removeFixed") cfg.fixedAmounts = (cfg.fixedAmounts || []).filter(function (v) { return v !== set.removeFixed; });
      else if (k === "addExclude") cfg.exclude = (cfg.exclude || []).filter(function (x) { return !(x.key === set.addExclude.key && x.value === set.addExclude.value); }).concat([set.addExclude]);
      else cfg[k] = set[k];
    }
    return cfg;
  }
  // Deterministic reading of a free-text note: what is recognised becomes a rule, the rest is kept as a note
  // with no effect on the numbers. No LLM: nothing leaves the browser.
  function interpret(text, M) {
    var out = { understood: [], notes: [] };
    String(text || "").split(/[\n;!?]+|\.(?=\s|$)/).map(function (x) { return x.trim(); }).filter(Boolean).forEach(function (o) {
      var n = norm(o), m, hit = [], many = /(surtout|principalement|essentiellement|majorit|uniquement|que de|que du|100)/.test(n);
      if ((m = n.match(/cycle[a-z ]*?(\d+)\s*(jours?|j|semaines?|mois)\b/))) { var d = +m[1] * (/^s/.test(m[2]) ? 7 : /^m/.test(m[2]) ? 30 : 1); hit.push({ label: "Cycle de vente attendu : " + d + " jours", set: { cycle: d } }); }
      if ((m = n.match(/(?:win rate|taux de (?:closing|conversion|transformation|signature|reussite))[a-z ]*?(\d{1,2})(?:\s*(?:a|et)\s*(\d{1,2}))?/))) { var a = +m[1], b = m[2] ? +m[2] : a + 5; if (!m[2]) a = Math.max(1, a - 5); hit.push({ label: "Win rate attendu : " + a + " à " + b + NB + "%", set: { wrMin: a, wrMax: b } }); }
      else if (many && /(inbound|entrant)/.test(n)) hit.push({ label: "Deals surtout entrants : win rate attendu 30 à 45" + NB + "%", set: { wrMin: 30, wrMax: 45 } });
      else if (many && /(outbound|prospection a froid|cold)/.test(n)) hit.push({ label: "Deals surtout en prospection à froid : win rate attendu 10 à 20" + NB + "%", set: { wrMin: 10, wrMax: 20 } });
      if (/(prix fixe|forfait|offre|tarif|abonnement|licence|pack)/.test(n) && (m = o.match(/(\d[\d\s\u00a0.,]*)\s*(k€|k\b|€|euros?)/i))) { var v = parseFloat(m[1].replace(/[\s\u00a0]/g, "").replace(",", ".")) * (/k/i.test(m[2]) ? 1000 : 1); if (v > 0) hit.push({ label: "Offre à prix fixe : " + fmt.int(v) + NB + "€", set: { addFixed: v } }); }
      if ((m = n.match(/stagn[a-z ]*?(\d+(?: \d)?)\s*(?:x|fois)/))) { var mu = parseFloat(m[1].replace(" ", ".")); if (mu >= 1 && mu <= 6) hit.push({ label: "Stagnation au-delà de " + String(mu).replace(".", ",") + " fois la durée médiane", set: { stagMult: mu } }); }
      if (/(fin de mois|dernier jour du mois|debut de mois|1er du mois|premier du mois)/.test(n) && /(factur|demarr|contrat|normal|voulu|regle|toujours)/.test(n)) hit.push({ label: "Close dates de fin de mois : assumées", set: { eomOk: true } });
      if (/qualifi/.test(n)) M.stages.forEach(function (st, i) { if (n.indexOf(norm(st)) >= 0) hit.push({ label: "Deal qualifié à partir de " + st, set: { qualStage: i } }); });
      M.reasons.forEach(function (r) {
        var rn = norm(r.name); if (r.name === "(vide)" || n.indexOf(rn) < 0) return; var rest = n.replace(rn, " ");
        var cls = /(ne repond|plus de nouvelle|plus de reponse|silence|fantome|ghost|sans decision|pas de decision|ne donne plus|abandonne)/.test(rest) ? "nd" : /concurren/.test(rest) ? "comp" : /(trop cher|prix|tarif)/.test(rest) ? "price" : /(fourre tout|par defaut|on ne sait pas|ne veut rien dire)/.test(rest) ? "vague" : null;
        if (cls) { var set = { reasons: {} }; set.reasons[r.name] = cls; hit.push({ label: "« " + r.name + " » lu comme : " + CLS[cls], set: set }); }
      });
      if (/(ignor|exclu|tenir compte|tenez pas compte|sans compter|hors |retir|enlev)/.test(n)) ["source", "segment"].forEach(function (key) { (M.values[key] || []).forEach(function (val) { if (norm(val).length > 1 && (" " + n + " ").indexOf(" " + norm(val)) >= 0) hit.push({ label: "Deals exclus : " + key + " « " + val + " »", set: { addExclude: { key: key, value: val } } }); }); });
      else if (M.rules.pipelines.length > 1) M.rules.pipelines.forEach(function (pp) { if (n.indexOf(norm(pp.name)) >= 0) hit.push({ label: "Pipeline analysé : " + pp.name, set: { pipeline: pp.name } }); });
      if (hit.length) hit.forEach(function (h) { h.source = o; out.understood.push(h); }); else out.notes.push(o);
    });
    return out;
  }

  // ---------- 6. movements between two snapshots (référentiel §2.3, N3) ----------
  // deal tuple: [id, stageIndex, status 0 open / 1 won / 2 lost, amount, closeDay, ownerHash]
  function diff(prev, cur) {
    var pm = {}, cm = {}, map = prev.stages.map(function (n) { return cur.stages.indexOf(n); });
    var mv = { from: prev.date, to: cur.date, created: [], won: [], lost: [], gone: [], pushed: [], pulled: 0, amount: [], regressed: [], advanced: 0, owner: 0 };
    prev.deals.forEach(function (d) { pm[d[0]] = d; }); cur.deals.forEach(function (d) { cm[d[0]] = d; });
    cur.deals.forEach(function (c) {
      var p = pm[c[0]];
      if (!p) { if (c[2] === 0) mv.created.push(c); else if (c[2] === 1) { mv.created.push(c); mv.won.push(c); } else { mv.created.push(c); mv.lost.push(c); } return; }
      if (p[2] !== 0) return;
      if (c[2] === 1) return mv.won.push(c);
      if (c[2] === 2) return mv.lost.push(c);
      if (c[4] && p[4] && c[4] > p[4]) mv.pushed.push({ d: c, days: Math.round((c[4] - p[4]) / DAY), old: p[4] }); else if (c[4] && p[4] && c[4] < p[4]) mv.pulled++;
      if (c[3] !== p[3]) mv.amount.push({ d: c, old: p[3] });
      var ps = p[1] >= 0 ? map[p[1]] : -1; if (c[1] >= 0 && ps >= 0) { if (c[1] < ps) mv.regressed.push({ d: c, from: prev.stages[p[1]] }); else if (c[1] > ps) mv.advanced++; }
      if (c[5] !== p[5]) mv.owner++;
    });
    var prevOpen = prev.deals.filter(function (d) { return d[2] === 0; });
    prevOpen.forEach(function (p) { if (!cm[p[0]]) mv.gone.push(p); });
    mv.prevOpen = prevOpen.length; mv.slippage = prevOpen.length ? mv.pushed.length / prevOpen.length * 100 : null;
    // forecast proxy (H1): what happened to the deals that were due to close during the interval
    var due = prevOpen.filter(function (d) { return d[4] > prev.date && d[4] <= cur.date; }), st = function (d) { var c = cm[d[0]]; return !c ? "gone" : c[2] === 1 ? "won" : c[2] === 2 ? "lost" : c[4] > d[4] ? "pushed" : "open"; };
    mv.due = { n: due.length, won: 0, lost: 0, pushed: 0, open: 0, gone: 0 }; due.forEach(function (d) { mv.due[st(d)]++; });
    return mv;
  }

  var api = { diff: diff, applyRule: applyRule, interpret: interpret, parseCSV: parseCSV, proposeMapping: proposeMapping, fieldLabel: fieldLabel, isPiiField: isPiiField, FIELDS: FIELDS, REQUIRED: REQUIRED, anonymize: anonymize, analyze: analyze, fmt: fmt };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.BIF = api;
})(typeof window !== "undefined" ? window : globalThis);

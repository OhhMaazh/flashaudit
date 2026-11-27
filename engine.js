/* Flash Sales Funnel Audit — browser engine.
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
      // columns the mapping did not recognise but that hold a few distinct labels (deal type, product, country…) are kept as business categories
      var dimCols = cols.filter(function (c) {
        if (c.field || c.pii) return false; var seen = {}, k = 0, num = 0, tot = 0;
        for (var r = 0; r < parsed.rows.length; r++) { var v = (parsed.rows[r][c.index] || "").trim(); if (!v) continue; tot++; if (/^[\d\s.,€$%\-\/:]+$/.test(v)) num++; if (!seen[v]) { seen[v] = 1; if (++k > 12) return false; } }
        return k >= 2 && num < tot / 2 && tot >= parsed.rows.length * 0.5;
      });
      var deals = parsed.rows.map(function (r) {
        var d = { entered: stageCols.map(function (c) { return parseDate(fix(c, r[c.index])); }), x: {} }; dimCols.forEach(function (c) { d.x["x" + c.index] = (r[c.index] || "").trim(); });
        cols.forEach(function (c) { if (!c.field || c.field === "stage_entered") return; var v = r[c.index]; d[c.field] = c.pii ? (v ? cache[v] : "") : fix(c, v); });
        return d;
      });
      return { deals: deals, vault: vault, hashedValues: hashed, uniqueHashed: jobs.length, piiColumns: piiCols.map(function (c) { return c.source; }), stageNames: stageCols.map(function (c) { return c.stage; }), dims: dimCols.map(function (c) { return { key: "x" + c.index, label: c.source }; }) };
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
      var d = { id: r.deal_id, stage: r.stage || "", status: status, created: parseDate(r.created_at), amount: parseAmount(r.amount), owner: r.owner_id || "", company: r.company_id || "", source: (r.source || "").trim(), segment: (r.segment || "").trim(), reason: (r.lost_reason || "").trim(), pipeline: (r.pipeline || "").trim(), entered: r.entered, hasClose: !!r.close_date, lastAct: parseDate(r.last_activity_at), label: r.deal_label || "", x: r.x || {} };
      var cd = parseDate(r.close_date), ca = parseDate(r.closed_at);
      d.closed = status === "open" ? null : (ca || cd); d.close = cd;
      [d.created, d.closed, d.lastAct].concat(d.entered).forEach(function (v) { if (v && v > snap) snap = v; });
      return d;
    }).filter(function (d) { return d.created; });
    var pipes = groupBy(deals, function (d) { return d.pipeline || "—"; });
    // several pipelines in one export: analyse the largest one unless told otherwise ("*" = all together)
    var pipeNames = Object.keys(pipes).sort(function (a, b) { return pipes[b].length - pipes[a].length; }), pipeUsed = cfg.pipeline === "*" ? null : (cfg.pipeline && pipes[cfg.pipeline] ? cfg.pipeline : (pipeNames.length > 1 ? pipeNames[0] : null));
    if (pipeUsed) deals = pipes[pipeUsed];
    // business categories found in the file (source, segment, any low-cardinality column): the user can set some of them aside
    var dimOf = function (d, key) { return key === "source" || key === "segment" ? d[key] : (d.x[key] || ""); };
    var dims = [{ key: "source", label: "Source" }, { key: "segment", label: "Segment" }].concat(anon.dims || []).map(function (dm) {
      var g = groupBy(deals.filter(function (d) { return dimOf(d, dm.key); }), function (d) { return dimOf(d, dm.key); });
      return { key: dm.key, label: dm.label, values: Object.keys(g).map(function (v) { return { v: v, n: g[v].length }; }).sort(function (a, b) { return b.n - a.n; }) };
    }).filter(function (dm) { return dm.values.length >= 2 && dm.values.length <= 12; });
    var monthsAll = deals.length ? Math.round((snap - Math.min.apply(null, deals.map(function (d) { return d.created; }))) / DAY / 30.4) : 0;
    var distinct = function (key) { return Object.keys(groupBy(deals.filter(function (d) { return d[key]; }), function (d) { return d[key]; })); }, values = { source: distinct("source"), segment: distinct("segment") };
    var excl = cfg.exclude || [];
    if (excl.length) deals = deals.filter(function (d) { return !excl.some(function (x) { return norm(dimOf(d, x.key)) === norm(x.value); }); });
    if (cfg.minAmount) deals = deals.filter(function (d) { return d.amount == null || d.amount >= cfg.minAmount; });
    if (cfg.since) { var cut = snap - cfg.since * 30.4 * DAY; deals = deals.filter(function (d) { return d.status === "open" || d.created >= cut; }); }
    // keep only the stage columns the analysed deals actually went through
    var keep = []; for (var s0 = 0; s0 < S; s0++) if (deals.some(function (d) { return d.entered[s0]; })) keep.push(s0);
    var stageNames = keep.map(function (k) { return anon.stageNames[k]; }); S = keep.length; level = S ? "N2" : "N1";
    deals.forEach(function (d) { d.entered = keep.map(function (k) { return d.entered[k]; }); d.maxStage = -1; d.firstStage = -1; for (var i = 0; i < S; i++) if (d.entered[i]) { d.maxStage = i; if (d.firstStage < 0) d.firstStage = i; } });
    // stage display names: reuse the spelling found in the data when it matches a stage-entered column
    var spelled = {}; deals.forEach(function (d) { spelled[norm(d.stage)] = d.stage; });
    var stages = stageNames.map(function (s) { return spelled[norm(s)] || s.charAt(0).toUpperCase() + s.slice(1); });
    if (!S) stages = Object.keys(groupBy(deals.filter(function (d) { return d.status === "open"; }), function (d) { return d.stage; }));
    var stageIx = {}; stages.forEach(function (s, i) { stageIx[norm(s)] = i; });
    var cfIx = cfg.cycleFrom != null && stageIx[cfg.cycleFrom] != null ? stageIx[cfg.cycleFrom] : -1;
    deals.forEach(function (d) { d.age = (snap - d.created) / DAY; d.cycle = d.closed ? (d.closed - (cfIx >= 0 && d.entered[cfIx] ? d.entered[cfIx] : d.created)) / DAY : null; var k = stageIx[norm(d.stage)]; d.cur = d.status === "open" ? (k != null ? k : d.maxStage) : -1; });

    var open = deals.filter(function (d) { return d.status === "open"; }), won = deals.filter(function (d) { return d.status === "won"; }), lost = deals.filter(function (d) { return d.status === "lost"; });
    var amt = function (d) { return d.amount || 0; }, openEur = sum(open, amt);
    var mature = deals.filter(function (d) { return d.created <= snap - 120 * DAY; }), cohort = mature.length >= deals.length * 0.3 ? mature : deals;
    var reached = function (d, i) { return d.status === "won" || d.maxStage >= i; };
    var M = { level: level, snap: snap, stages: stages, checks: [], locked: [] };
    var add = function (id, label, status, value, thr, n, text, x) {
      var c = { id: id, fam: id[0], label: label, status: status, value: value, thr: thr, n: n, text: text, indicative: n != null && n < 30 };
      if (n != null && n < 10 && status !== "na") { c.status = "na"; c.value = "trop peu de deals"; c.text = label + " : pas assez de deals pour conclure (" + n + ")."; }
      for (var k in x || {}) c[k] = x[k]; M.checks.push(c); return c;
    };

    // --- funnel (K1, K12) on the creation cohort ---
    var cw = cohort.filter(function (d) { return d.status === "won"; }), cl = cohort.filter(function (d) { return d.status === "lost"; });
    var qual = cohort.filter(function (d) { return d.status !== "open" && (S < 2 || reached(d, Math.min(qs, S - 1))); });
    var k2 = pc(qual.filter(function (d) { return d.status === "won"; }).length, qual.length), k3 = pc(sum(qual.filter(function (d) { return d.status === "won"; }), amt), sum(qual, amt));
    var recentWon = won.filter(function (d) { return d.closed >= snap - 365 * DAY && d.cycle != null; }), k4 = recentWon.length >= 8 ? med(recentWon.map(function (d) { return d.cycle; })) : null;
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
      add("A6", "Deals créés en étape avancée", low(a6, 10, 25), fmt.pct(a6), "< 10 % · 10–25 % · > 25 %", deals.length, fmt.pct(a6) + " des deals apparaissent directement en étape avancée.", { act: "Créez le deal dès le premier contact qualifié, pas au moment du devis.", reco: "Créez le deal dès le premier échange sérieux, et faites-le créer automatiquement depuis vos formulaires de contact.", horizon: "quick", group: 1 });
    }

    // --- B conversion ---
    var wrRed = Math.max(10, wrMin / 2), wrTxt = "la fourchette attendue de " + wrMin + " à " + wrMax + NB + "%";
    add("B2", "Win rate vs fourchette attendue", k2 == null ? "na" : k2 >= wrMin ? "g" : k2 >= wrRed ? "o" : "r", k2 == null ? "—" : fmt.pct(k2), wrMin + "–" + wrMax + " % attendu · < " + Math.round(wrRed) + " % rouge", qual.length, k2 == null ? "" : "Win rate de " + fmt.pct(k2) + " sur les deals qualifiés, " + (k2 >= wrMin ? (k2 > wrMax ? "au-dessus de " : "dans ") : "sous ") + wrTxt + ".", { cause: "Qualification trop permissive à l’entrée, ou ciblage hors de la clientèle idéale.", act: "Durcissez la qualification à l’entrée, avant de travailler le closing.", reco: "Le problème est rarement la conclusion : écrivez ce qu’un deal doit avoir pour entrer dans le pipeline (un besoin exprimé, un interlocuteur qui décide, une échéance), et refusez le reste.", group: 3 });
    var b3 = k2 != null && k3 != null ? k2 - k3 : null;
    add("B3", "Win rate en montant vs en nombre", low(b3, 10, 20), b3 == null ? "—" : (b3 >= 0 ? "−" : "+") + Math.abs(b3).toFixed(1).replace(".", ",") + NB + "pts", "écart > 10 pts orange · > 20 rouge", qual.length, b3 == null ? "" : "Win rate de " + fmt.pct(k3) + " en montant contre " + fmt.pct(k2) + " en nombre.", { act: "Passez en revue vos dix plus gros deals perdus.", reco: "Relisez vos dix plus gros deals perdus. Au-dessus d’un certain montant, prévoyez un parcours à part : plusieurs interlocuteurs côté client, un responsable chez vous.", group: 3 });
    var wk = function (d) { return Math.floor((snap - d.created) / (7 * DAY)); }, last4 = deals.filter(function (d) { return wk(d) < 4; }).length / 4, prev12 = deals.filter(function (d) { var w = wk(d); return w >= 4 && w < 16; }).length / 12;
    var b4 = prev12 ? (last4 - prev12) / prev12 * 100 : null;
    var per = [0, 1, 2, 3].map(function (k) { return deals.filter(function (d) { var w = wk(d); return w >= k * 4 && w < k * 4 + 4; }).length; }), b4red = per[0] < per[1] && per[1] < per[2] && per[2] < per[3];
    if (deals.length && (snap - Math.min.apply(null, deals.map(function (d) { return d.created; }))) / DAY < 112) b4 = null;
    add("B4", "Création de pipeline", b4 == null ? "na" : b4red ? "r" : b4 < -20 ? "o" : "g", b4 == null ? "—" : (b4 >= 0 ? "+" : "−") + Math.abs(Math.round(b4)) + NB + "%", "baisse > 20 % sur 4 semaines = orange", Math.round(prev12 * 12), b4 == null ? "" : b4red ? "La création de pipeline baisse depuis trois périodes de quatre semaines consécutives." : b4 < -20 ? "La création de pipeline recule de " + Math.abs(Math.round(b4)) + NB + "% sur quatre semaines." : "La création de pipeline tient : " + Math.round(last4) + " deals par semaine sur les quatre dernières.", { act: "Fixez un objectif de création de deals par semaine et par commercial.", reco: "Un objectif de nouveaux deals par semaine et par commercial, et des créneaux de prospection bloqués dans l’agenda.", group: 4, chart: "monthly" });
    var seg = function (key) {
      var g = groupBy(qual.filter(function (d) { return d[key]; }), function (d) { return d[key]; }), tot = cohort.filter(function (d) { return d[key]; }).length;
      return Object.keys(g).map(function (k) { var a = g[k], w = a.filter(function (d) { return d.status === "won"; }); return { name: k, n: a.length, wr: pc(w.length, a.length), vol: pc(cohort.filter(function (d) { return d[key] === k; }).length, tot), cycle: med(w.filter(function (d) { return d.cycle != null; }).map(function (d) { return d.cycle; })) }; }).filter(function (x) { return x.n >= 10; }).sort(function (a, b) { return b.wr - a.wr; });
    };
    var mix = function (id, label, key, word, none, needCycle) {
      var list = seg(key); M[key + "s"] = list; if (list.length < 2) return add(id, label, "na", "—", "", null, "");
      var best = list[0], weak = list.filter(function (x) { return x.n >= 30 && x.vol > 20 && x.wr < best.wr / 2 && (!needCycle || (x.cycle && best.cycle && x.cycle > 1.5 * best.cycle)); })[0];
      add(id, label, weak ? "r" : "g", weak ? fmt.pct(weak.wr) + " vs " + fmt.pct(best.wr) : fmt.pct(list[list.length - 1].wr) + " à " + fmt.pct(best.wr), "> 20 % du volume et win rate < moitié du meilleur = rouge", sum(list, function (x) { return x.n; }), weak ? word + " « " + weak.name + " » pèse " + fmt.pct(weak.vol) + " du volume et convertit à " + fmt.pct(weak.wr) + ", contre " + fmt.pct(best.wr) + " pour « " + best.name + " »." : none + " ne décroche : de " + fmt.pct(list[list.length - 1].wr) + " à " + fmt.pct(best.wr) + " de win rate.", { act: "Qualifiez plus durement « " + (weak ? weak.name : "") + " », ou déplacez l’effort vers ce qui convertit.", reco: "Demandez plus de garanties avant d’ouvrir un deal venu de « " + (weak ? weak.name : "") + " », ou mettez ce temps sur ce qui signe.", group: 3, chart: key });
    };
    mix("B5", "Conversion par source", "source", "La source", "Aucune source"); mix("I1", "Performance par segment", "segment", "Le segment", "Aucun segment", true);
    if (S >= 4) {
      var lateL = cl.filter(function (d) { return d.maxStage >= S - 2; }), earlyL = cl.filter(function (d) { return d.maxStage <= 1; }), b6 = pc(lateL.length, cl.length), g2 = pc(earlyL.length, cl.length);
      var cB6 = add("B6", "Pertes en fin de funnel", b6 == null ? "na" : b6 > 50 ? "r" : "g", fmt.pct(b6), "> 50 % des pertes aux deux dernières étapes = rouge", cl.length, fmt.pct(b6) + " des pertes surviennent en " + stages[S - 2] + " ou en " + stages[S - 1] + ".", { detail: fmt.int(lateL.length) + " deals perdus après le chiffrage, soit " + fmt.eur(sum(lateL, amt)) + ".", impact: sum(lateL, amt), cause: "Les deals avancent sans être qualifiés : décideur jamais rencontré, pas d’échéance côté client.", potential: (function () { var li = M.funnel[S - 2].conv < M.funnel[S - 1].conv ? S - 2 : S - 1, gain = 0.10 * M.funnel[li].reached * downFrom(li); return "Dix points de conversion de plus en " + M.funnel[li].name + " : environ " + Math.round(gain) + " deals gagnés de plus sur la cohorte, soit " + fmt.eur(gain * basket) + "."; })(), act: "N’envoyez plus de proposition sans décideur identifié.", reco: "Fixez ce qu’un deal doit avoir validé avant toute proposition : le décideur rencontré, le problème chiffré avec le client, une échéance de son côté.", group: 3, chart: "loss", absorbs: ["G2"] });
      (function () { var li = M.funnel[S - 2].conv < M.funnel[S - 1].conv ? S - 2 : S - 1, gain = 0.10 * M.funnel[li].reached * downFrom(li); cB6.lateN = lateL.length; cB6.lateEur = sum(lateL, amt); cB6.share = b6; cB6.gainStage = M.funnel[li].name; cB6.gainConv = M.funnel[li].conv; cB6.gainN = Math.round(gain); cB6.gainEur = gain * basket; })();
      add("G2", "Disqualification précoce", g2 == null ? "na" : g2 > 40 ? "g" : g2 >= 20 ? "o" : "r", fmt.pct(g2), "> 40 % des pertes tôt = vert · < 20 % rouge", cl.length, "Seulement " + fmt.pct(g2) + " des pertes arrivent aux deux premières étapes.", { act: "Faites sortir plus tôt les deals qui ne se feront pas.", reco: "Écrivez les cas où l’on arrête un deal tôt, et félicitez en revue ceux qui le font : un deal perdu tôt coûte moins cher qu’un deal perdu tard.", group: 3, chart: "loss" });
      var worst = M.funnel.slice().sort(function (a, b) { return b.lostEur - a.lostEur; })[0], lostTot = sum(M.funnel, function (f) { return f.lostEur; }), b1 = worst && pc(worst.lostEur, lostTot);
      M.leak = worst && b1 > 30 && worst.conv < 60 ? worst.name : null;
      add("B1", "Fuite à une étape", M.leak ? "r" : "g", worst ? fmt.pct(worst.conv) : "—", "conversion faible et > 30 % des € perdus = rouge", worst ? worst.reached : null, M.leak ? "L’étape " + worst.name + " ne laisse passer que " + fmt.pct(worst.conv) + " des deals et concentre " + fmt.pct(b1) + " des montants perdus." : "Aucune étape ne concentre les pertes.", { act: "Travaillez en priorité l’étape " + (worst ? worst.name : "") + "\u00a0: c’est là que les montants se perdent.", reco: "Travaillez ce qui se joue à l’étape " + (worst ? worst.name : "") + " : le chiffrage du problème avec le client, l’accès à celui qui décide, un plan d’étapes partagé jusqu’à la signature.", group: 3, chart: "funnel", impact: worst ? worst.lostEur : 0, absorbedBy: "B6" });
    }

    // --- C velocity ---
    var autoDays = basket < 1e4 ? 60 : basket < 25e3 ? 90 : basket < 5e4 ? 120 : basket < 1e5 ? 180 : 270, alertDays = +cfg.cycle || autoDays;
    add("C1", "Cycle de vente vs attendu", k4 == null ? "na" : k4 <= alertDays ? "g" : k4 <= alertDays * 1.5 ? "o" : "r", k4 == null ? "—" : fmt.days(k4), (cfg.cycle ? "cycle attendu déclaré : " : "zone d’alerte pour ce panier : ") + alertDays + " j", recentWon.length, k4 == null ? "" : "Cycle médian de " + fmt.days(k4) + " pour un panier médian de " + fmt.eur(basket) + (k4 <= alertDays ? " : cohérent." : " : au-delà " + (cfg.cycle ? "du cycle attendu (" : "de la zone d’alerte (") + alertDays + NB + "j)."), { cause: "Une étape goulot, ou des deals non qualifiés qui traînent.", act: "Trouvez l’étape qui ralentit vos ventes avant de toucher au closing.", reco: "Cherchez l’étape où vos deals attendent le plus : c’est elle qu’il faut raccourcir, pas la conclusion.", group: 4, chart: "time" });
    var stag = [], c3 = null, c4 = null;
    // a deal is at rest after `stagDays` in its current stage when the user gave a rule, otherwise beyond `mult` times the normal duration
    var sd = +cfg.stagDays || 0, stLim = cfg.stageDays || {}, rest = function (d) { return S ? (d.cur >= 0 && d.entered[d.cur] ? (snap - d.entered[d.cur]) / DAY : null) : d.age; };
    var isStag = function (d, T) { var t = rest(d); if (t == null) return false; var own = S && d.cur >= 0 ? stLim[norm(stages[d.cur])] : 0; if (own) return t > own; return T ? t > T : S ? !!k5[d.cur] && t > mult * k5[d.cur] : !!k4 && t > mult * k4; };
    if (S) {
      var tot5 = sum(k5.filter(Boolean)), bott = k5.map(function (v, i) { return { i: i, sh: v ? v / tot5 * 100 : 0 }; }).sort(function (a, b) { return b.sh - a.sh; })[0];
      add("C2", "Étape goulot", low(bott.sh, 30, 40), fmt.pct(bott.sh), "> 30 % du cycle orange · > 40 % rouge", recentWon.length, "L’étape " + stages[bott.i] + " consomme " + fmt.pct(bott.sh) + " du cycle.", { act: "Anticipez ce qui fait attendre les deals en " + stages[bott.i] + ".", reco: "Listez ce que vous attendez de l’extérieur à l’étape " + stages[bott.i] + " (juridique, technique, achats) et lancez-le une étape plus tôt.", group: 4, chart: "time" });
      stag = open.filter(function (d) { return isStag(d, sd); });
      c3 = pc(sum(stag, amt), openEur);
      add("C3", "Deals stagnants", low(c3, 15, 30), fmt.pct(c3), "< 15 % · 15–30 % · > 30 % du pipeline en €", open.length, fmt.pct(c3) + " du pipeline ouvert stagne : " + stag.length + " deals " + (sd ? "dans la même étape depuis plus de " + sd + " jours." : "sans mouvement depuis plus de " + mx + " la durée médiane de leur étape."), { impact: sum(stag, amt), act: "Requalifiez ou fermez les " + stag.length + " deals sans mouvement.", reco: "Une alerte automatique quand un deal dépasse " + (sd ? sd + " jours dans son étape" : (mult === 2 ? "deux" : mx.replace("×", "")) + " fois la durée normale de son étape") + " : il est relancé ou fermé.", horizon: "quick", group: 2, chart: "pipe" });
    }
    if (k4) { var old = open.filter(function (d) { return d.age > 2 * k4; }); c4 = pc(old.length, open.length); add("C4", "Âge du pipeline ouvert", low(c4, 10, 25), fmt.pct(c4), "< 10 % · 10–25 % · > 25 %", open.length, fmt.pct(c4) + " des deals ouverts ont plus de deux fois l’âge d’un cycle gagnant (" + fmt.days(2 * k4) + ").", { act: "Sortez du pipeline les deals trop anciens pour se signer.", reco: "Fermez-les ou repartez de zéro avec le client, et ne les comptez plus dans votre prévision.", horizon: "quick", group: 4, chart: "age" }); }
    if (!S && k4) { stag = open.filter(function (d) { return isStag(d, sd); }); c3 = pc(sum(stag, amt), openEur); add("C3", "Deals stagnants (approché par l’âge)", low(c3, 15, 30), fmt.pct(c3), "< 15 % · 15–30 % · > 30 % du pipeline en €", open.length, fmt.pct(c3) + " du pipeline ouvert a plus de " + mx + " l’âge d’un cycle gagnant : " + stag.length + " deals.", { impact: sum(stag, amt), act: "Requalifiez ou fermez ces " + stag.length + " deals.", reco: "Fermez ces deals ou repartez de zéro avec le client, puis installez une alerte automatique sur l’ancienneté.", horizon: "quick", group: 2, chart: "pipe" }); }

    // --- D data hygiene ---
    var miss = [["amount", "montant", function (d) { return d.amount == null; }], ["close_date", "close date", function (d) { return !d.hasClose; }], ["owner", "commercial", function (d) { return !d.owner; }], ["source", "source", function (d) { return !d.source; }]].map(function (f) { return { key: f[0], label: f[1], miss: pc(open.filter(f[2]).length, open.length) || 0 }; });
    M.completeness = miss; var d1 = miss.slice().sort(function (a, b) { return b.miss - a.miss; })[0];
    add("D1", "Champs clés vides", low(d1.miss, 5, 15), fmt.pct(d1.miss, 1), "< 5 % · 5–15 % · > 15 % par champ", open.length, d1.miss < 5 ? "Les champs clés sont renseignés : au plus " + fmt.pct(d1.miss, 1) + " de vides (" + d1.label + ")." : fmt.pct(d1.miss) + " des deals ouverts n’ont pas de " + d1.label + ".", { act: "Rendez le montant et la close date obligatoires dès qu’un deal est qualifié.", reco: "Montant et date de signature obligatoires à partir de l’étape où le deal est sérieux, pas à la création.", horizon: "quick", group: 1 });
    var past = open.filter(function (d) { return d.close && d.close < snap; }), d2 = pc(past.length, open.length);
    add("D2", "Close date dépassée", low(d2, 5, 15), fmt.pct(d2), "< 5 % · 5–15 % · > 15 % des deals ouverts", open.length, fmt.pct(d2) + " des deals ouverts ont une close date déjà passée (" + fmt.eur(sum(past, amt)) + ").", { impact: sum(past, amt), act: "Mettez à jour ou fermez les deals dont la date de signature est passée.", reco: "Une alerte une semaine avant chaque date de signature, et l’impossibilité de garder une date passée sur un deal ouvert.", horizon: "quick", group: 1, chart: "close" });
    if (deals.some(function (d) { return d.lastAct; })) { var idleDays = basket < 1e4 ? 14 : 30, idle = open.filter(function (d) { return !d.lastAct || (snap - d.lastAct) / DAY > idleDays; }), d5 = pc(idle.length, open.length); add("D5", "Deals sans activité", low(d5, 15, 30), fmt.pct(d5), "< 15 % · 15–30 % · > 30 % des deals ouverts", open.length, fmt.pct(d5) + " des deals ouverts n’ont eu aucune activité depuis " + idleDays + " jours (" + fmt.eur(sum(idle, amt)) + ").", { cause: "Activités non enregistrées dans le CRM, ou deals abandonnés sans être fermés.", impact: sum(idle, amt), act: "Vérifiez que les e-mails et les rendez-vous remontent dans le CRM, puis fermez les deals abandonnés.", reco: "Vérifiez d’abord que les e-mails et les agendas sont reliés au CRM ; ensuite, fermeture automatique après 60 jours sans échange.", horizon: "quick", group: 4.5 }); }
    var withAmt = deals.filter(function (d) { return d.amount > 0; }), freq = groupBy(withAmt.filter(function (d) { return fixed.indexOf(d.amount) < 0; }), function (d) { return d.amount; }), modeV = Object.keys(freq).sort(function (a, b) { return freq[b].length - freq[a].length; })[0], d6 = modeV ? pc(freq[modeV].length, withAmt.length) : null;
    var freqAll = groupBy(withAmt, function (d) { return d.amount; }), modeAll = Object.keys(freqAll).sort(function (a, b) { return freqAll[b].length - freqAll[a].length; })[0], modeAllShare = modeAll ? pc(freqAll[modeAll].length, withAmt.length) : 0;
    var phOpen = open.filter(function (d) { return d.amount === +modeV; });
    add("D6", "Montants par défaut", d6 == null ? "na" : d6 > 30 ? "r" : d6 >= 10 ? "o" : "g", fmt.pct(d6), "> 30 % sur une même valeur = rouge", withAmt.length, fmt.pct(d6) + " des deals portent exactement le même montant : " + fmt.int(+modeV) + NB + "€.", { detail: "Une valeur par défaut, pas une estimation : " + fmt.eur(sum(phOpen, amt)) + " du pipeline ouvert reposent dessus.", impact: sum(phOpen, amt), cause: "Valeur par défaut du CRM, ou montant saisi seulement au moment du closing.", act: "Exigez un montant estimé dès la qualification du deal.", reco: "Supprimez la valeur par défaut ; un montant estimé devient obligatoire quand le deal est sérieux.", horizon: "quick", group: 4.5, chart: "amounts", mode: +modeV });
    var comp = groupBy(open.filter(function (d) { return d.company; }), function (d) { return d.company; }), compK = Object.keys(comp), d7 = pc(compK.filter(function (k) { return comp[k].length > 1; }).length, compK.length);
    add("D7", "Doublons par entreprise", low(d7, 3, 10), d7 == null ? "—" : fmt.pct(d7, 1), "< 3 % · 3–10 % · > 10 %", compK.length, d7 == null ? "" : fmt.pct(d7, 1) + " des entreprises ont plusieurs deals ouverts.", { act: "Regroupez les deals ouverts en double sur une même entreprise.", reco: "Un seul deal ouvert par entreprise et par besoin, et un responsable par compte.", horizon: "quick", group: 4.5 });
    var defClass = function (name) { var n = norm(name); return !n || /^(vide|autre|autres|other|sans suite|n a|na|inconnu|unknown|divers)$/.test(n) ? "vague" : /(budget|report|no decision|sans decision|statu quo|abandon|timing|plus de besoin|pas de besoin|silence|sans reponse)/.test(n) ? "nd" : /(concurr|competit)/.test(n) ? "comp" : /(prix|price|tarif|cher)/.test(n) ? "price" : "other"; }, classOf = function (name) { return rc[name] || defClass(name); };
    var reasons = groupBy(lost, function (d) { return d.reason || "(vide)"; });
    M.reasons = Object.keys(reasons).map(function (k) { return { name: k, n: reasons[k].length, eur: sum(reasons[k], amt), cls: classOf(k) }; }).sort(function (a, b) { return b.n - a.n; });
    var rs = function (c) { return M.reasons.filter(function (x) { return x.cls === c; }); }, rn = function (a) { return sum(a, function (x) { return x.n; }); }, re = function (a) { return sum(a, function (x) { return x.eur; }); };
    var vagueR = rs("vague"), ndR = rs("nd"), vague = pc(rn(vagueR), lost.length), usable = lost.length - rn(vagueR), g4 = pc(rn(ndR), usable);
    add("D8", "Raisons de perte inexploitables", vague == null ? "na" : vague > 40 ? "r" : "g", fmt.pct(vague), "> 40 % vides ou fourre-tout = rouge", lost.length, vague > 40 ? fmt.pct(vague) + " des raisons de perte ne disent rien : " + vagueR.map(function (x) { return x.name === "(vide)" ? "champ vide" : "« " + x.name + " »"; }).join(", ") + "." : "Les raisons de perte sont exploitables : " + fmt.pct(vague) + " de valeurs vides ou fourre-tout.", { detail: "C’est d’abord un problème de saisie : tant que la raison est un fourre-tout, impossible de savoir contre quoi vous perdez." + (g4 != null ? " Parmi les raisons exploitables, " + fmt.pct(g4) + " sont des pertes sans décision de l’acheteur." : ""), cause: "Liste de raisons trop vague et champ non contrôlé : le commercial choisit la valeur la plus rapide à saisir.", impact: re(vagueR), act: "Refaites la liste des raisons de perte et rendez-la obligatoire.", reco: "Six raisons précises, obligatoires pour fermer un deal ; retirez « Autre » ; séparez « le client n’a rien décidé » de « un concurrent a gagné ».", horizon: "quick", group: 3, chart: "reasons", absorbs: ["G4"], share: vague, names: vagueR.map(function (x) { return x.name; }), nd: g4 });

    // --- G method ---
    add("G4", "Pertes sans décision", low(g4, 30, 50), fmt.pct(g4), "< 30 % · 30–50 % · > 50 % des raisons exploitables", usable, fmt.pct(g4) + " des pertes renseignées sont sans décision de l’acheteur.", { detail: "On perd contre le statu quo, pas contre un concurrent : " + fmt.eur(re(ndR)) + " concernés.", cause: "Valeur ou urgence non établies ; aucun événement déclencheur côté client.", impact: re(ndR), act: "Faites établir l’urgence du client avant toute proposition.", reco: "Dès le premier échange, faites dire au client ce que lui coûte de ne rien faire, et pourquoi maintenant ; chiffrez-le avec lui avant toute proposition.", group: 3, chart: "reasons" });
    var fast = won.filter(function (d) { return d.cycle != null && d.cycle < 7; }), g6 = pc(fast.length, won.length);
    add("G6", "Deals gagnés sans parcours", low(g6, 10, 25), fmt.pct(g6, 1), "< 10 % · 10–25 % · > 25 %", won.length, fmt.pct(g6, 1) + " des deals gagnés le sont en moins de sept jours.", { act: "Mettez à part les deals signés en moins d’une semaine\u00a0: ils faussent vos moyennes.", reco: "Rangez à part les demandes déjà mûres, et vérifiez que ces deals n’ont pas été créés après coup, une fois signés.", group: 4.5 });

    // --- H forecast discipline ---
    var eom = function (t) { return new Date(t + DAY).getUTCDate() === 1; }, withClose = open.filter(function (d) { return d.close; }), h3 = pc(withClose.filter(function (d) { return eom(d.close); }).length, withClose.length);
    add("H3", "Close dates en fin de mois", cfg.eomOk ? (h3 == null ? "na" : "g") : low(h3, 20, 40), fmt.pct(h3), "< 20 % · 20–40 % · > 40 %", withClose.length, fmt.pct(h3) + " des close dates tombent le dernier jour du mois" + (cfg.eomOk ? ", ce qui correspond à votre règle de démarrage ou de facturation." : "."), { act: "Reliez chaque date de signature à un événement côté client.", reco: "Une date de signature correspond à un événement chez le client (un comité, une fin de contrat) ; sinon le deal n’a pas de date.", horizon: "quick", group: 4, chart: "close" });
    var last5 = function (t) { var d = new Date(t), n = 0, x = new Date(Date.UTC(d.getUTCFullYear(), d.getUTCMonth() + 1, 0)); while (x.getTime() > t) { var w = x.getUTCDay(); if (w && w < 6) n++; x = new Date(x.getTime() - DAY); } return n < 5; };
    var h2 = pc(won.filter(function (d) { return d.closed && last5(d.closed); }).length, won.length);
    add("H2", "Signatures concentrées en fin de mois", low(h2, 35, 50), fmt.pct(h2), "< 35 % · 35–50 % · > 50 %", won.length, fmt.pct(h2) + " des deals gagnés se signent dans les cinq derniers jours ouvrés du mois.", { act: "Ne liez plus vos remises à la fin du mois.", reco: "Accordez une remise contre une contrepartie (durée, volume, témoignage), jamais parce que le mois se termine : vos clients ont appris à attendre.", group: 4 });

    // --- E people (always phrased by stage and skill, never by name) ---
    var off = cfg.ownersOff || [], isOut = function (d) { return d.status === "open" && (stag.indexOf(d) >= 0 || !!(d.close && d.close < snap)); };
    var owners = groupBy(deals.filter(function (d) { return d.owner; }), function (d) { return d.owner; }), codes = Object.keys(owners).sort(function (a, b) { return owners[b].length - owners[a].length; });
    M.reps = codes.map(function (h, i) {
      var q = qual.filter(function (d) { return d.owner === h; }), w = owners[h].filter(function (d) { return d.status === "won"; });
      return { hash: h, code: "Commercial " + String.fromCharCode(65 + i % 26), closed: q.length, wr: q.length >= 15 ? pc(q.filter(function (d) { return d.status === "won"; }).length, q.length) : null, wonEur: sum(w, amt), open: owners[h].filter(function (d) { return d.status === "open"; }).length, total: owners[h].length, off: off.indexOf(h) >= 0, lastCreated: Math.max.apply(null, owners[h].map(function (d) { return d.created; })), openEur: sum(owners[h].filter(function (d) { return d.status === "open"; }), amt), stalledN: owners[h].filter(isOut).length, stalledEur: sum(owners[h].filter(isOut), amt),
        stageConv: M.funnel.map(function (f, s) { var a = cohort.filter(function (d) { return d.owner === h && reached(d, s); }), b = s < S - 1 ? a.filter(function (d) { return reached(d, s + 1); }) : a.filter(function (d) { return d.status === "won"; }); return a.length >= 15 ? { n: a.length, conv: pc(b.length, a.length) } : null; }) };
    });
    var cmp = M.reps.filter(function (r) { return r.wr != null && !r.off; });
    if (cmp.length >= 4) {
      var mean = sum(cmp, function (r) { return r.wr; }) / cmp.length, cv = Math.sqrt(sum(cmp, function (r) { return Math.pow(r.wr - mean, 2); }) / cmp.length) / mean;
      add("E1", "Écarts de win rate entre commerciaux", low(cv, 0.25, 0.45), cv.toFixed(2).replace(".", ","), "CV < 0,25 · 0,25–0,45 · > 0,45", sum(cmp, function (r) { return r.closed; }), cv < 0.25 ? "La méthode est partagée : le win rate varie peu d’un commercial à l’autre." : "Le win rate varie fortement d’un commercial à l’autre.", { act: "Faites de la méthode de vos meilleurs celle de toute l’équipe.", reco: "Écoutez les rendez-vous de vos meilleurs, écrivez ce qu’ils font à chaque étape, et faites-en la méthode commune.", group: 5, chart: "reps" });
      var top = M.reps.slice().sort(function (a, b) { return b.wonEur - a.wonEur; }).slice(0, Math.max(1, Math.ceil(M.reps.length * 0.2))), e4 = pc(sum(top, function (r) { return r.wonEur; }), sum(M.reps, function (r) { return r.wonEur; }));
      add("E4", "Concentration de la performance", low(e4, 40, 60), fmt.pct(e4), "< 40 % · 40–60 % · > 60 %", sum(cmp, function (r) { return r.closed; }), fmt.pct(e4) + " du montant gagné vient de " + top.length + " commerciaux sur " + M.reps.length + ".", { act: "Documentez ce que font vos meilleurs et vérifiez la répartition des comptes.", reco: "Écrivez ce que font vos meilleurs, et vérifiez que les comptes et les demandes entrantes sont répartis équitablement.", group: 5, chart: "reps" });
      var flags = [];
      M.reps.forEach(function (r) { if (r.off) return; r.stageConv.forEach(function (c, s) { if (c && M.funnel[s].conv && c.conv < 0.7 * M.funnel[s].conv) flags.push({ rep: r, s: s, conv: c.conv, n: c.n, team: M.funnel[s].conv }); }); });
      flags = flags.filter(function (f) { return flags.filter(function (g) { return g.s === f.s; }).length <= cmp.length / 2; }).sort(function (a, b) { return a.conv / a.team - b.conv / b.team; });
      var e2 = flags[0]; M.blocked = e2 ? { hash: e2.rep.hash, stage: e2.s } : null;
      add("E2", "Blocage individuel à une étape", !S ? "na" : e2 ? "r" : "g", e2 ? fmt.pct(e2.conv) + " vs " + fmt.pct(e2.team) : "aucun", "conversion < 0,7× l’équipe sur une étape = rouge", e2 ? e2.n : sum(cmp, function (r) { return r.closed; }), e2 ? "Un commercial convertit " + fmt.pct(e2.conv) + " de ses deals en " + stages[e2.s] + ", contre " + fmt.pct(e2.team) + " pour l’équipe." : "Aucun commercial ne décroche de l’équipe sur une étape précise.", { detail: e2 ? "Écart mesuré sur " + e2.n + " deals arrivés à cette étape. L’équipe est dans la norme : c’est une compétence précise, pas un problème collectif." : "", impact: e2 ? (e2.team - e2.conv) / 100 * e2.n * downFrom(e2.s) * basket : 0, cause: "Une compétence propre à cette étape (chiffrage, business case, accès au décideur), pas la méthode collective.", potential: e2 ? "Au niveau de l’équipe, ce commercial gagnerait environ " + Math.round((e2.team - e2.conv) / 100 * e2.n * downFrom(e2.s)) + " deals de plus sur la cohorte." : "", act: e2 ? "Accompagnez ce commercial sur l’étape " + stages[e2.s] + "\u00a0: écoutez ses rendez-vous." : "", reco: e2 ? "Assistez à deux de ses rendez-vous à l’étape " + stages[e2.s] + ", travaillez un seul point à la fois, et fixez un objectif sur cette étape à 30 jours." : "", group: 5, chart: "reps", conv: e2 ? e2.conv : null, team: e2 ? e2.team : null, stageName: e2 ? stages[e2.s] : "", gainN: e2 ? Math.round((e2.team - e2.conv) / 100 * e2.n * downFrom(e2.s)) : 0 });
    }

    var orph = open.filter(function (d) { return off.indexOf(d.owner) >= 0; });
    if (off.length) add("E8", "Deals sans porteur", orph.length ? "r" : "g", orph.length + " deals", "tout deal ouvert a un porteur en activité", open.length, orph.length ? orph.length + " deals ouverts, " + fmt.eur(sum(orph, amt)) + ", sont portés par " + (off.length > 1 ? "des personnes qui ne vendent" : "une personne qui ne vend") + " plus chez vous." : "Aucun deal ouvert n’est porté par quelqu’un qui ne vend plus.", { impact: sum(orph, amt), act: "Réattribuez ces " + orph.length + " deals cette semaine.", reco: "Réattribuez ces deals à un porteur nommé, ou fermez-les. À chaque départ, aucun compte désactivé tant que ses deals n’ont pas de nouveau porteur.", horizon: "quick", group: 2, orphN: orph.length });

    // --- pattern P1: stagnant ∪ outdated pipeline (absorbs C3, D2, H3, C4) ---
    var byId = {}; M.checks.forEach(function (c) { byId[c.id] = c; });
    var uni = open.filter(function (d) { return stag.indexOf(d) >= 0 || (d.close && d.close < snap); }), both = stag.filter(function (d) { return d.close && d.close < snap; });
    M.pipe = { open: openEur, n: open.length, stagOnly: sum(stag, amt) - sum(both, amt), both: sum(both, amt), pastOnly: sum(past, amt) - sum(both, amt), union: sum(uni, amt), unionN: uni.length };
    // every open deal, ordered so that the pipeline strip reads as: alive | at rest | at rest and overdue | overdue
    var grp = function (d) { var a = stag.indexOf(d) >= 0, b = !!(d.close && d.close < snap); return a && b ? 2 : a ? 1 : b ? 3 : 0; };
    M.openDeals = open.map(function (d) { var t = rest(d); return { id: d.id, label: d.label, owner: d.owner, amount: amt(d), stage: d.stage, rest: t == null ? null : Math.round(t), past: !!(d.close && d.close < snap), close: d.close, g: grp(d), def: isStag(d, 0), lim: (S && d.cur >= 0 && stLim[norm(stages[d.cur])]) || null, fixed: d.amount != null && d.amount === +modeAll, source: d.source, segment: d.segment, x: d.x }; }).sort(function (a, b) { return a.g - b.g || (a.rest || 0) - (b.rest || 0); });
    var unionAt = function (T) { var a = open.filter(function (d) { return isStag(d, T) || (d.close && d.close < snap); }); return { days: T, n: a.length, eur: sum(a, amt) }; }, stOpt = [30, 60, 90].map(unionAt), stDef = unionAt(0);
    var isBad = function (id) { return byId[id] && (byId[id].status === "o" || byId[id].status === "r"); };
    if (isBad("C3") && isBad("D2")) {
      var p1 = pc(M.pipe.union, openEur);
      M.checks.push({ id: "P1", fam: "P", pattern: true, label: "Pipeline fictif", status: "r", critical: true, value: fmt.pct(p1), n: open.length, thr: "C3 et D2 hors du vert", text: fmt.pct(p1) + " du pipeline ouvert est inactif ou périmé.", detail: uni.length + " deals stagnants ou à close date dépassée : " + fmt.eur(M.pipe.union) + " sur " + fmt.eur(openEur) + " ouverts. La couverture réelle est plus basse qu’elle n’en a l’air.", impact: M.pipe.union, cause: "Aucune règle de purge : les deals restent ouverts pour tenir la couverture, et la revue juge le volume plutôt que le mouvement.", act: "Requalifiez ou fermez ces " + uni.length + " deals\u00a0: votre pipeline redevient lisible.", reco: "Relancez ou fermez ces " + uni.length + " deals, puis installez une alerte automatique sur la durée passée dans chaque étape.", horizon: "quick", group: 2, chart: "pipe", absorbs: ["C3", "D2", "H3", "C4", "D5"] });
    }

    // --- findings: hierarchy of référentiel §8, absorbed symptoms removed ---
    var absorbed = {}; M.checks.forEach(function (c) { if ((c.status === "r" || c.status === "o") && c.absorbs) c.absorbs.forEach(function (a) { absorbed[a] = c.id; }); });
    if (isBad("B6")) absorbed.B1 = "B6";
    var rank = { r: 0, o: 1 };
    M.findings = M.checks.filter(function (c) { return (c.status === "r" || c.status === "o") && !absorbed[c.id] && c.group; }).sort(function (a, b) { return a.group - b.group || rank[a.status] - rank[b.status] || (b.impact || 0) - (a.impact || 0); });
    M.top = M.findings.filter(function (c) { return c.status === "r" || c.impact; }).slice(0, 5); M.others = M.findings.filter(function (c) { return M.top.indexOf(c) < 0; });
    M.good = ["B2", "E1", "D1", "A3", "E4", "H2", "B4", "D8"].map(function (id) { return byId[id]; }).filter(function (c) { return c && c.status === "g"; }).slice(0, 3);
    M.absorbed = absorbed;
    [["D3", "Close dates repoussées", "N3"], ["D4", "Mises à jour en rafale", "N3"], ["E7", "Reports de close date par commercial", "N3"], ["F3", "Deals qui changent de commercial", "N3"], ["H1", "Fiabilité des prévisions", "N3"], ["H4", "Prévisions volontairement basses", "N3"], ["D5", "Deals sans activité", "N4"], ["E5", "Montée en puissance des nouveaux", "N4"], ["E6", "Couverture par commercial", "N4"], ["F1", "Passage de relais entre prospection et vente", "N4"], ["F2", "Délai de prise en charge", "N4"], ["G1", "Critères de sortie", "Contexte"], ["G3", "Qualification de façade", "Contexte"]]
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
    M.rules = { eomOk: !!cfg.eomOk, exclude: excl, qualStage: Math.min(qs, Math.max(S - 1, 0)), stagMult: mult, wrMin: wrMin, wrMax: wrMax, cycle: +cfg.cycle || null, cycleAuto: autoDays, fixedAmounts: fixed, stagDays: sd || null, ownersOff: off, since: cfg.since || null, stageDays: stLim, minAmount: cfg.minAmount || null, cycleFrom: cfIx >= 0 ? stages[cfIx] : null, pipeline: pipeUsed, pipelines: pipeNames.map(function (k) { return { name: k, n: pipes[k].length }; }) };
    // ---------- what the tool understood of this business: every truth is assumed until the user confirms or corrects it ----------
    var ans = cfg.answers || {}, T = [], qt = function (s) { return "«" + NB + s + NB + "»"; };
    var stK = Object.keys(stLim), stTxt = stK.length ? " (sauf " + stK.map(function (k) { var i = stages.map(norm).indexOf(k); return "en " + qt(i >= 0 ? stages[i] : k) + " : " + stLim[k] + " jours"; }).join(", ") + ")" : "";
    var stateOf = function (id) {
      if (id === "pipeline") return pipeUsed ? "je juge le pipeline " + qt(pipeUsed) : "je juge tous vos pipelines ensemble";
      if (id === "since") return cfg.since ? "je ne juge que les deals créés depuis " + cfg.since + " mois" : "je juge tout l’historique";
      if (id === "stale") return sd ? "un deal est à l’arrêt après " + sd + " jours " + (S ? "dans la même étape" : "sans signature") : stDefTxt;
      if (id.indexOf("reason:") === 0) { var nm = id.slice(7), c = classOf(nm); return qt(nm) + (c === "nd" ? " veut dire que le prospect ne répond plus" : c === "comp" ? " veut dire qu’un concurrent a gagné" : c === "price" ? " veut dire que le prix a bloqué" : c === "vague" ? " est la case qu’on coche par défaut" : " est une vraie raison de perte"); }
      if (id === "fixed") return modeTxt + (fixed.indexOf(+modeAll) >= 0 ? " est un prix de votre catalogue" : " n’est pas un tarif");
      if (id === "eom") return cfg.eomOk ? "dater à fin de mois est votre règle" : "les dates de fin de mois sont mises par défaut";
      if (id === "qual") return "un deal est sérieux à partir de " + qt(stages[Math.min(qs, S - 1)]);
      if (id === "cycle") return "une vente normale dure jusqu’à " + alertDays + " jours chez vous";
      if (id === "motion") return "un taux de signature normal chez vous va de " + wrMin + " à " + wrMax + NB + "%";
      return "";
    };
    var truth = function (o) {
      o.answer = ans[o.id] != null ? ans[o.id] : null;
      if (o.kind === "multi") { var on = o.options.filter(function (x) { return x.on; }); o.said = o.answer != null || on.length ? o.saidFn(on) : null; delete o.saidFn; }
      else o.said = o.answer == null ? null : typeof o.answer === "number" && o.options[o.answer] ? o.options[o.answer].said : stateOf(o.id);
      if (o.id === "stale" && stTxt) { o.assumed += stTxt; if (o.said) o.said += stTxt; }
      T.push(o); return o;
    };
    if (pipeNames.length > 1) truth({ id: "pipeline", topic: "Ce que je juge", interview: true, ev: "pipelines", ask: "Votre fichier mélange " + pipeNames.length + " pipelines. Lequel dois-je juger ?", why: "Mélanger deux pipelines fausse toutes les moyennes.", assumed: "je juge le plus gros, " + qt(pipeNames[0]),
      options: pipeNames.slice(0, 4).map(function (pn) { return { label: pn, sub: fmt.int(pipes[pn].length) + " deals", set: { pipeline: pn }, said: "je juge le pipeline " + qt(pn), note: "Je ne regarde que " + qt(pn) + "." }; }).concat([{ label: "Tous ensemble", set: { pipeline: "*" }, said: "je juge tous vos pipelines ensemble", note: "Je les juge ensemble." }]) });
    if (monthsAll >= 14) truth({ id: "since", topic: "Ce que je juge", ask: "Votre fichier remonte à " + monthsAll + " mois. Je juge tout, ou seulement la période récente ?", why: "Si votre équipe ou votre offre a changé, les vieux deals faussent le jugement. Les deals encore ouverts sont toujours gardés.", assumed: "je juge les " + monthsAll + " mois de votre fichier",
      options: [{ label: "Tout", set: { since: null }, said: "je juge tout l’historique" }, { label: "Les 12 derniers mois", set: { since: 12 }, said: "je ne juge que les deals créés depuis 12 mois" }, { label: "Les 6 derniers mois", set: { since: 6 }, said: "je ne juge que les deals créés depuis 6 mois" }] });
    dims.forEach(function (dm) {
      truth({ id: "dim:" + dm.key, topic: "Ce que je juge", kind: "multi", interview: /(type|categorie|nature|business|motion|offre|produit|product)/.test(norm(dm.label)), ev: "dim", dim: dm.key,
        ask: "Votre fichier range vos deals par " + qt(dm.label) + ". Y a-t-il des valeurs que je ne dois pas juger ?", why: "Renouvellements, partenaires, tests : touchez ce qui n’est pas de la vente à juger ici. Tout se recalcule sans ces deals.", assumed: "je juge tous vos deals, quelle que soit leur valeur de " + qt(dm.label),
        saidFn: function (on) { return on.length ? "je mets de côté " + on.map(function (x) { return qt(x.label); }).join(", ") : "je juge toutes les valeurs de " + qt(dm.label); },
        options: dm.values.map(function (v) { return { label: v.v, sub: fmt.int(v.n) + " deals", on: excl.some(function (x) { return x.key === dm.key && norm(x.value) === norm(v.v); }), set: { toggleExclude: { key: dm.key, value: v.v } } }; }) });
    });
    if (M.reps.length >= 2) {
      var susp = M.reps.filter(function (r) { return !r.off && r.open >= 3 && r.lastCreated < snap - 90 * DAY; })[0];
      truth({ id: "team", topic: "Votre équipe", kind: "multi", who: true, interview: !!susp,
        ask: susp ? "{who:" + susp.hash + "} porte encore " + susp.open + " deals ouverts mais n’en a créé aucun depuis " + Math.round((snap - susp.lastCreated) / DAY / 30.4) + " mois. Qui ne vend plus chez vous ?" : M.reps.length + " personnes portent des deals dans votre fichier. Y en a-t-il qui ne vendent plus chez vous ?",
        why: "Départs, managers, comptes de test : je les sors des comparaisons entre commerciaux, et je vous montre les deals qu’ils portent encore.", assumed: "les " + M.reps.length + " personnes de votre fichier vendent toujours chez vous",
        saidFn: function (on) { return on.length ? on.length + (on.length > 1 ? " personnes ne vendent" : " personne ne vend") + " plus chez vous" : "les " + M.reps.length + " personnes de votre fichier vendent toujours chez vous"; },
        options: M.reps.map(function (r) { return { who: r.hash, label: r.code, sub: fmt.int(r.total) + " deals", on: r.off, set: { toggleOwner: r.hash } }; }) });
    }
    var stDefTxt = S ? "un deal est à l’arrêt quand il reste dans une étape " + (mult === 2 ? "deux" : mx.replace("×", "")) + " fois plus longtemps que la normale" : "un deal est à l’arrêt quand il est ouvert depuis " + (mult === 2 ? "deux" : mx.replace("×", "")) + " fois la durée d’une vente gagnée";
    if (open.length >= 5) truth({ id: "stale", topic: "Deal à l’arrêt", interview: true, ev: "rest", ask: (k4 ? "Chez vous, une vente gagnée se signe en " + Math.round(k4) + " jours. " : "") + (S ? "Au bout de combien de temps sans changer d’étape un deal est-il à l’arrêt ?" : "Au bout de combien de temps un deal ouvert est-il à l’arrêt ?"),
      why: "C’est la règle qui pèse le plus sur le verdict : elle décide de ce qui compte encore dans votre pipeline.", assumed: stDefTxt,
      options: stOpt.map(function (o) { return { label: o.days === 30 ? "Un mois" : o.days === 60 ? "Deux mois" : "Trois mois", sub: o.n + " deals à l’arrêt", set: { stagDays: o.days }, said: "un deal est à l’arrêt après " + o.days + " jours " + (S ? "dans la même étape" : "sans signature"), note: "Avec votre règle : " + o.n + " deals à l’arrêt, " + fmt.eur(o.eur) + "." }; })
        .concat([{ label: "Gardez votre règle", sub: stDef.n + " deals à l’arrêt", set: { stagDays: null }, said: stDefTxt, note: "Je garde ma règle : " + stDef.n + " deals à l’arrêt, " + fmt.eur(stDef.eur) + "." }]) });
    var firstReason = true;
    M.reasons.forEach(function (x) {
      var sh = pc(x.n, lost.length); if (x.name === "(vide)" || defClass(x.name) !== "vague" || sh < 10) return;
      var a = { reasons: {} }, b = { reasons: {} }; a.reasons[x.name] = "nd"; b.reasons[x.name] = "vague";
      truth({ id: "reason:" + x.name, topic: "Raisons de perte", interview: firstReason, ev: "reasons", hl: x.name, ask: fmt.pct(sh) + " de vos deals perdus sont classés " + qt(x.name) + ". Quand un commercial coche ça, il veut dire quoi ?", why: "Selon votre réponse, c’est un sujet de saisie ou une vraie cause de perte.", assumed: qt(x.name) + " est une case par défaut, qui ne dit pas pourquoi vous perdez",
        options: [{ label: "Le prospect ne répond plus", set: a, said: qt(x.name) + " veut dire que le prospect ne répond plus", note: qt(x.name) + " devient une vraie cause de perte : le silence du prospect." }, { label: "Rien de précis, c’est la case par défaut", set: b, said: qt(x.name) + " est la case qu’on coche par défaut", note: "Ces deals sont comptés comme perdus sans raison connue." }, { label: "Je ne sais pas", set: b, said: "personne ne sait ce que veut dire " + qt(x.name), note: "Je la compte comme une raison inconnue." }] });
      firstReason = false;
    });
    var phA = open.filter(function (d) { return d.amount === +modeAll; }), modeTxt = fmt.int(+modeAll) + NB + "€";
    if (modeAllShare >= 10) truth({ id: "fixed", topic: "Montants", interview: true, ev: "amounts", ask: (phA.length >= 3 ? phA.length + " deals ouverts affichent" : fmt.pct(modeAllShare) + " de vos deals affichent") + " exactement " + modeTxt + ". C’est le prix d’une de vos offres ?", why: "Si c’est un tarif, ces montants sont justes. Sinon, une partie de votre pipeline repose sur un chiffre que personne n’a estimé.", assumed: modeTxt + " est un montant mis en attendant, pas un vrai prix",
      options: [{ label: "Oui, c’est notre tarif", set: { addFixed: +modeAll }, said: modeTxt + " est un prix de votre catalogue", note: "Je ne vous en reparlerai pas." }, { label: "Non, un montant mis en attendant", set: { removeFixed: +modeAll }, said: modeTxt + " n’est pas un tarif", note: fmt.eur(sum(phA, amt)) + " de votre pipeline reposent sur des montants que personne n’a chiffrés." }, { label: "Je ne sais pas", set: { removeFixed: +modeAll }, said: "personne ne sait si " + modeTxt + " est un vrai prix", note: "Je le compte comme un montant non chiffré." }] });
    if (h3 != null && h3 >= 20) truth({ id: "eom", topic: "Dates de signature", ask: fmt.pct(h3) + " de vos dates de signature tombent le dernier jour du mois. C’est une règle chez vous ?", why: "Si vous datez toujours à fin de mois, c’est normal. Sinon, ce sont des dates mises pour remplir la case.", assumed: "ces dates de fin de mois sont mises par défaut",
      options: [{ label: "Oui, on date à fin de mois", set: { eomOk: true }, said: "dater à fin de mois est votre règle" }, { label: "Non, c’est la date mise par défaut", set: { eomOk: false }, said: "les dates de fin de mois sont mises par défaut" }, { label: "Je ne sais pas", set: { eomOk: false }, said: "personne ne sait pourquoi vos dates tombent en fin de mois" }] });
    if (S >= 3) truth({ id: "qual", topic: "Votre vente", ask: "À partir de quelle étape un deal est-il vraiment sérieux chez vous ?", why: "Je calcule votre taux de signature sur les deals qui ont atteint cette étape.", assumed: "un deal est sérieux à partir de " + qt(stages[Math.min(qs, S - 1)]),
      options: stages.map(function (st, i) { return { label: st, set: { qualStage: i }, said: "un deal est sérieux à partir de " + qt(st) }; }) });
    if (k4 != null) truth({ id: "cycle", topic: "Votre vente", ask: "Une vente gagnée se signe chez vous en " + Math.round(k4) + " jours. Quelle durée visez-vous ?", why: "Je m’en sers pour dire si vos ventes sont trop lentes.", assumed: "pour des deals de " + fmt.eur(basket) + ", une vente normale dure jusqu’à " + autoDays + " jours",
      options: [[30, "Un mois"], [60, "Deux mois"], [90, "Trois mois"], [180, "Six mois ou plus"]].map(function (o) { return { label: o[1], set: { cycle: o[0] }, said: "vous visez une vente en " + o[0] + " jours" }; }) });
    if (k2 != null) truth({ id: "motion", topic: "Votre vente", ask: "D’où viennent surtout vos deals ?", why: "Un taux de signature normal n’est pas le même : 30 à 45" + NB + "% sur des demandes entrantes, 10 à 20" + NB + "% en prospection.", assumed: "vos deals mêlent demandes entrantes et prospection (17 à 30" + NB + "% de signature attendus)",
      options: [{ label: "Des demandes entrantes", set: { wrMin: 30, wrMax: 45 }, said: "vos deals viennent surtout de demandes entrantes" }, { label: "De la prospection", set: { wrMin: 10, wrMax: 20 }, said: "vos deals viennent surtout de la prospection" }, { label: "Un mélange", set: { wrMin: 17, wrMax: 30 }, said: "vos deals mêlent demandes entrantes et prospection" }] });
    M.truths = T; M.dims = dims; M.eom = h3; M.monthsAll = monthsAll;
    var EX = [], slow = -1; k5.forEach(function (v, i) { if (v && (slow < 0 || v > k5[slow])) slow = i; });
    if (open.length >= 5) EX.push({ k: "stale", text: "Chez nous, un deal sans nouvelle depuis 45 jours est à l’arrêt." });
    if (S && slow >= 0) EX.push({ k: "stage", text: "Un deal peut rester " + Math.max(30, Math.ceil(3 * k5[slow] / 15) * 15) + " jours en " + stages[slow] + ", c’est normal chez nous." });
    var exRep = M.reps.filter(function (r) { return !r.off && r.open >= 3 && r.lastCreated < snap - 90 * DAY; })[0] || M.reps.filter(function (r) { return !r.off; }).slice(-1)[0];
    if (M.reps.length >= 2 && exRep) EX.push({ k: "team", text: "{who:" + exRep.hash + "} ne vend plus chez nous." });
    if (modeAllShare >= 10 && fixed.indexOf(+modeAll) < 0) EX.push({ k: "fixed", text: fmt.int(+modeAll) + " €, c’est le prix de notre offre." });
    var exR = M.reasons.filter(function (x) { return x.name !== "(vide)" && x.cls === "vague" && pc(x.n, lost.length) >= 10; })[0];
    if (exR) EX.push({ k: "reason", text: "« " + exR.name + " » veut dire que le prospect ne répond plus." });
    var exD = dims.filter(function (dm) { return !excl.some(function (x) { return x.key === dm.key; }); })[0];
    if (exD) EX.push({ k: "dim", text: "Ne comptez pas les deals « " + exD.values[exD.values.length - 1].v + " »." });
    if (monthsAll >= 14 && !cfg.since) EX.push({ k: "since", text: "Jugez seulement les 12 derniers mois." });
    if (k4 && !cfg.cycle) EX.push({ k: "cycle", text: "Chez nous, une vente dure " + (k4 > 75 ? "six" : "trois") + " mois." });
    if (!cfg.minAmount) EX.push({ k: "min", text: "Ne comptez pas les deals de moins de 1 000 €." });
    M.examples = EX;

    // ---------- the story told to a sales director: verdict, three answers, and for every weakness the audit, the finding and a recommended solution ----------
    // (solutions: docs/referentiel-solutions.md — the whole key is given, the offer to do it together comes after)
    var byC = {}; M.checks.forEach(function (c) { byC[c.id] = c; });
    var W10 = ["zéro", "une", "deux", "trois", "quatre", "cinq", "six", "sept", "huit", "neuf", "dix"], cap = function (s) { return s.charAt(0).toUpperCase() + s.slice(1); }, x10 = function (p) { return Math.max(1, Math.min(9, Math.round(p / 10))); };
    var tOf = function (id) { return T.filter(function (x) { return x.id === id; })[0]; }, shareSt = pc(M.pipe.union, openEur) || 0, alive = openEur - M.pipe.union, nSt = M.pipe.unionN, B = [];
    var twice = mult === 2 ? "deux fois" : mx.replace("×", "") + " fois", serious = S ? stages[Math.min(qs, S - 1)] : "";
    var limits = S ? stages.map(function (st, i) { var v = stLim[norm(st)] || sd || (k5[i] ? Math.max(7, Math.round(mult * k5[i])) : 0); return v ? st + " " + v + NB + "j" : ""; }).filter(Boolean).join(", ") : "";
    var hasOwn = Object.keys(stLim).length > 0, after = " Passé ce délai, le deal est relancé ou fermé.";
    var alertRule = S && limits && (!sd || hasOwn) ? "Dans votre CRM, une alerte dès qu’un deal dépasse la durée limite de son étape : " + limits + ". " + (sd || hasOwn ? (sd ? "Ce sont les règles que vous m’avez données." : "Ce sont vos règles là où vous m’en avez donné, et ailleurs " + twice + " votre durée normale.") : "C’est " + twice + " votre durée normale à chaque étape, calculée sur vos propres deals, pas un chiffre standard.") + after
      : sd ? "Dans votre CRM, une alerte dès qu’un deal passe " + sd + " jours " + (S ? "dans la même étape" : "sans signature") + " : c’est la règle que vous m’avez donnée." + after
      : "Dans votre CRM, une alerte dès qu’un deal est ouvert depuis plus de " + (k4 ? Math.round(mult * k4) + " jours, soit " + twice + " la durée d’une vente gagnée chez vous." : twice + " la durée d’une vente gagnée chez vous.") + after;
    if (shareSt >= 15 && nSt >= 3) B.push({ key: "stalled", ch: 0, tone: "r", title: "Les " + nSt + " deals à l’arrêt, commercial par commercial.", sub: fmt.eur(M.pipe.union) + " sur " + fmt.eur(openEur) + " : des deals qui ne bougent plus, ou qui devaient signer à une date déjà passée.", truths: ["stale", "team"],
      audit: "j’ai regardé vos " + open.length + " deals ouverts un par un : depuis quand chacun " + (S ? "est dans son étape" : "est ouvert") + ", et si sa date de signature est déjà passée.",
      decision: "d’ici vendredi, chaque commercial relance ou ferme ses deals à l’arrêt.", worthLabel: "Ce que ça change", worth: "votre prévision repart de " + fmt.eur(alive) + ", et vos revues de pipeline portent sur " + (open.length - nSt) + " deals au lieu de " + open.length + ".",
      unknown: "pourquoi ces deals n’avancent plus. C’est à voir deal par deal, avec ceux qui les portent.",
      sol: { name: (S ? "Une durée limite par étape" : "Une durée limite par deal") + ", et une revue de pipeline qui regarde ce qui bouge", start: "Relancer, c’est obtenir une prochaine étape datée, confirmée par le client. Sinon le deal est fermé : il pourra toujours être rouvert.", rule: alertRule,
        ritual: "En revue de pipeline, ne passez plus tous les deals en revue : seulement ceux en alerte, et ceux qui doivent signer dans le mois. Une seule question par deal : quelle est la prochaine étape, à quelle date, et le client l’a-t-il confirmée ?", sign: "moins de 15" + NB + "% de votre pipeline à l’arrêt. Aujourd’hui : " + fmt.pct(shareSt) + "." },
      slide: "Nous sortons " + nSt + " deals à l’arrêt de la prévision (" + fmt.eur(M.pipe.union) + "). Chacun relance ou ferme les siens d’ici vendredi.",
      message: "Bonjour à tous. J’ai passé notre pipeline en revue : " + nSt + " deals ne bougent plus ou ont une date de signature dépassée, pour " + fmt.eur(M.pipe.union) + ". D’ici vendredi, chacun relance ou ferme les siens : une prochaine étape datée, ou le deal sort du pipeline. À partir de lundi, notre prévision repart de " + fmt.eur(alive) + "." });
    if (byC.E8 && byC.E8.status === "r") B.push({ key: "orphans", ch: 0, tone: "r", title: byC.E8.orphN + " deals ouverts n’ont plus personne pour les porter.", sub: fmt.eur(byC.E8.impact) + " confiés à " + (off.length > 1 ? "des personnes qui ne vendent" : "quelqu’un qui ne vend") + " plus chez vous. Vous me l’avez appris, le fichier ne le disait pas.", truths: ["team"],
      audit: "j’ai croisé vos " + open.length + " deals ouverts avec les personnes que vous m’avez dit ne plus vendre chez vous.",
      decision: "cette semaine, réattribuez ces " + byC.E8.orphN + " deals, ou fermez-les.", worthLabel: "Ce que ça change", worth: "chaque deal ouvert a de nouveau quelqu’un pour le faire avancer.", unknown: "deals encore vivants, ou partis avec leur porteur ?",
      sol: { name: "Une passation en trois gestes à chaque départ", start: "Commencez par les deals les plus avancés.", rule: "À chaque départ, aucun compte n’est désactivé tant que ses deals ouverts n’ont pas un nouveau porteur, avec une note de passation écrite par la personne qui part : où en est le client, quelle est la suite prévue.",
        ritual: "Le nouveau porteur appelle chaque client dans les sept jours. Sans réponse après ses relances, le deal est fermé.", sign: "aucun deal ouvert porté par quelqu’un qui ne vend plus chez vous." },
      slide: "Nous réattribuons cette semaine " + byC.E8.orphN + " deals restés sans porteur (" + fmt.eur(byC.E8.impact) + ")." });
    var tf = tOf("fixed");
    if (tf) {
      var nPh = phA.length, ePh = fmt.eur(sum(phA, amt)), lead = nPh >= 3 ? nPh + " deals ouverts à " + modeTxt + " pile" : fmt.pct(modeAllShare) + " de vos deals à " + modeTxt + " pile", auditAm = "j’ai compté combien de vos " + fmt.int(withAmt.length) + " deals chiffrés portent exactement le même montant.";
      B.push(tf.answer === 0 || (tf.answer != null && fixed.indexOf(+modeAll) >= 0) ? { key: "amounts", ch: 0, half: true, tone: "g", audit: auditAm, title: modeTxt + " est un prix de votre catalogue : point levé.", sub: nPh >= 3 ? "Ces " + ePh + " sont de vrais montants." : "", truths: ["fixed"] }
        : tf.answer == null ? { key: "amounts", ch: 0, half: true, tone: "o", audit: auditAm, title: lead + " : vrai prix, ou case remplie ?", sub: "Répondez juste en dessous : selon le cas, c’est un tarif ou un trou dans votre prévision.", truths: ["fixed"], fact: lead, ask: "C’est le prix d’une de vos offres ?", stake: tf.why }
        : { key: "amounts", ch: 0, half: true, tone: "r", audit: auditAm, title: lead + (nPh >= 3 ? " : " + ePh + " que personne n’a chiffrés." : " : un montant que personne n’a chiffré."), sub: "", truths: ["fixed"], decision: "cette semaine, faites chiffrer ces " + (nPh >= 3 ? nPh + " " : "") + "deals par ceux qui les portent.", unknown: "montant rempli d’office à la création du deal, ou commerciaux qui ne chiffrent qu’au dernier moment ? Le réglage à faire dans le CRM n’est pas le même.",
          sol: { name: "Un montant demandé au bon moment, jamais rempli d’office", rule: "Supprimez la valeur par défaut du champ montant, et rendez-le obligatoire seulement " + (serious ? "à partir de l’étape " + qt(serious) : "quand le deal est sérieux") + ". Demandé plus tôt, le commercial ne peut pas le connaître : il invente.",
            ritual: "Tant que le chiffre n’est pas connu, une fourchette (petit, moyen, gros deal) vaut mieux qu’un montant inventé. Une fois par mois, vérifiez qu’aucun montant ne revient trop souvent.", sign: "plus aucun montant porté par plus d’un deal sur dix, hors tarifs de votre catalogue." },
          slide: "Nous chiffrons cette semaine les " + (nPh >= 3 ? nPh + " " : "") + "deals restés à " + modeTxt + " pile." });
    }
    var te = tOf("eom"), auditDt = "j’ai regardé quel jour tombe la date de signature prévue de vos " + withClose.length + " deals ouverts datés.";
    if (te) B.push(te.answer != null && cfg.eomOk ? { key: "dates", ch: 0, half: true, tone: "g", audit: auditDt, title: "Dater à fin de mois est votre règle : point levé.", sub: "", truths: ["eom"] }
      : te.answer == null ? { key: "dates", ch: 0, half: true, tone: "o", audit: auditDt, title: fmt.pct(h3) + " de vos dates de signature tombent le dernier jour du mois : règle maison, ou date par défaut ?", sub: "Répondez juste en dessous.", truths: ["eom"], fact: fmt.pct(h3) + " des dates de signature au dernier jour du mois", ask: "C’est une règle chez vous ?", stake: te.why }
      : { key: "dates", ch: 0, half: true, tone: "r", audit: auditDt, title: fmt.pct(h3) + " de vos dates de signature sont là pour remplir la case.", sub: "Ce ne sont pas des engagements de clients.", truths: ["eom"], decision: "ce mois-ci, une date de signature est une date donnée par le client, sinon le deal n’en a pas.", unknown: "dates posées à la création du deal, ou repoussées de mois en mois ? Un seul fichier ne le montre pas : il en faut deux, à une semaine d’écart.",
        sol: { name: "Une date de signature vient du client, pas du calendrier", start: "Un deal sans date sort de la prévision du mois, il ne disparaît pas.", rule: "Ajoutez un champ court, « ce qui justifie cette date » (un comité, la fin du contrat en cours, un démarrage voulu), obligatoire dès qu’un deal entre dans la prévision du mois.",
          ritual: "Chaque semaine, regardez les dates repoussées. Un report de plus de deux semaines, ou vers le mois suivant, signale un deal à risque : les chances de signer baissent à chaque report.", sign: "moins d’une date sur cinq le dernier jour du mois. Aujourd’hui : " + fmt.pct(h3) + "." } });
    var b6c = byC.B6 && byC.B6.status !== "na" ? byC.B6 : null, lateA = S >= 2 ? stages[S - 2] : "", lateB = S >= 1 ? stages[S - 1] : "", auditJ = "j’ai suivi " + fmt.int(cohort.length) + " deals d’étape en étape, de leur création à leur issue.";
    if (b6c && b6c.status === "r") B.push({ key: "journey", ch: 1, tone: "r", audit: auditJ, title: "Vous perdez en fin de parcours : " + fmt.int(b6c.lateN) + " deals perdus en " + lateA + " ou en " + lateB + ".", sub: fmt.pct(b6c.share) + " de toutes vos pertes arrivent là : " + fmt.eur(b6c.lateEur) + " chiffrés pour rien, une fois tout le travail fait.", truths: ["qual"],
      decision: "pendant un mois, aucun deal n’entre en " + lateA + " sans votre feu vert.", worthLabel: "Ce que ça vaut", worth: "si " + Math.round(b6c.gainConv + 10) + " deals sur 100 passent l’étape " + b6c.gainStage + " au lieu de " + Math.round(b6c.gainConv) + ", c’est environ " + b6c.gainN + " deals gagnés de plus, soit " + fmt.eur(b6c.gainEur) + ". Sans un lead de plus.",
      unknown: "deals poussés trop tôt en " + lateA + ", ou adressés à quelqu’un qui ne décide pas ?",
      sol: { name: "Trois conditions pour entrer en " + qt(lateA) + ", vérifiables côté client", start: "Votre feu vert est provisoire : il sert à voir ce qui manque aux deals qu’on vous présente.", rule: "Écrivez trois conditions pour entrer en " + lateA + ". Chacune est un acte du client, pas une impression du commercial : celui qui décide a participé à un échange ; le problème est chiffré avec le client ; une date de décision est convenue, avec les étapes pour y arriver.",
        ritual: "Relisez vos dix derniers deals perdus en " + lateA + " ou en " + lateB + " : laquelle de ces conditions manquait ? La liste qui en sort est la vôtre. Puis joignez à chaque proposition un plan d’étapes partagé avec le client, jusqu’à la signature.", sign: "moins d’une perte sur deux en fin de parcours. Aujourd’hui : " + fmt.pct(b6c.share) + "." },
      slide: "Pendant un mois, aucun deal n’entre en " + lateA + " sans feu vert : " + fmt.int(b6c.lateN) + " deals perdus à ce stade." });
    else if (S >= 2) B.push({ key: "journey", ch: 1, tone: M.leak ? "o" : "g", audit: auditJ, title: M.leak ? "C’est à l’étape " + M.leak + " que vos deals s’arrêtent le plus." : "Vos pertes sont réparties sur tout le parcours : aucune étape ne casse.", sub: M.leak ? "Elle concentre la plus grosse part des montants perdus." : "", truths: ["qual"] });
    else B.push({ key: "journey", ch: 1, tone: "na", title: "Votre fichier ne dit pas où vous perdez.", sub: "Il manque les dates de passage d’une étape à l’autre. Ajoutez-les à l’export pour voir le parcours d’un deal.", truths: [] });
    var e2c = byC.E2 && byC.E2.status === "r" ? byC.E2 : null;
    if (e2c) { var ra = Math.round(e2c.conv / 10), rb = Math.floor(e2c.team / 10), rbTxt = (e2c.team - rb * 10 >= 2 ? "plus de " : "") + rb;
      B.push({ key: "rep", ch: 1, tone: "r", audit: "j’ai comparé, étape par étape, la part de deals que chaque commercial fait passer (" + cmp.length + " commerciaux ont assez de deals pour être comparés).", title: ra < rb ? "Un commercial fait passer " + ra + " deals sur 10 en " + e2c.stageName + ". Le reste de l’équipe, " + rbTxt + "." : "Un commercial décroche de l’équipe à l’étape " + e2c.stageName + ".", sub: fmt.pct(e2c.conv) + " de ses deals passent l’étape " + e2c.stageName + ", contre " + fmt.pct(e2c.team) + " pour l’équipe. C’est à cette étape précise que l’écart se creuse, pas ailleurs.", truths: ["team"],
        decision: "ce mois-ci, relisez ensemble ses 5 derniers deals perdus en " + e2c.stageName + ".", worthLabel: "Ce que ça vaut", worth: "au niveau de l’équipe, ce serait environ " + e2c.gainN + " deals de plus, " + fmt.eur(e2c.impact) + "." + (b6c && b6c.gainStage === e2c.stageName ? " Ce montant fait partie des " + fmt.eur(b6c.gainEur) + " ci-dessus, il ne s’y ajoute pas." : ""),
        unknownLabel: "Ce que cet écran ne montre pas", unknown: "ce qui distingue ses deals de ceux des autres : taille, origine, délai avant d’arriver en " + e2c.stageName + ".",
        sol: { name: "Un accompagnement sur une seule étape, pas un plan de performance", w2: "La méthode", rule: "Comparez ses deals perdus à deux deals gagnés par un collègue à la même étape : cherchez une différence de préparation, pas de talent. Vérifiez d’abord que ses deals sont comparables aux autres : un portefeuille plus difficile explique parfois tout l’écart.",
          ritual: "Assistez à deux de ses rendez-vous à cette étape dans le mois. Un seul point à travailler à la fois, et un objectif sur cette étape seulement, à trente jours.", sign: "sa part de deals qui passent l’étape " + e2c.stageName + " rejoint celle de l’équipe (" + fmt.pct(e2c.team) + ")." } }); }
    var d8 = byC.D8 && byC.D8.status !== "na" ? byC.D8 : null, silent = M.reasons.filter(function (x) { return x.cls === "nd" && defClass(x.name) === "vague"; })[0], auditR = "j’ai lu la raison saisie sur chacun de vos " + fmt.int(lost.length) + " deals perdus.", rT = T.filter(function (x) { return x.id.indexOf("reason:") === 0; }).map(function (x) { return x.id; });
    if (d8 && d8.status === "r") { var xv = x10(d8.share);
      B.push({ key: "reasons", ch: 2, tone: "r", read: "A", audit: auditR, title: cap(W10[xv]) + " fois sur dix, vous ne savez pas pourquoi vous perdez.", sub: d8.names.map(function (nm) { return nm === "(vide)" ? "champ vide" : qt(nm); }).join(", ") + " : " + fmt.pct(d8.share) + " de vos pertes, soit " + fmt.eur(d8.impact) + " de deals fermés sans explication.", truths: rT,
        body: "C’est d’abord un sujet de saisie, pas de vente. Tant qu’il n’est pas réglé, impossible de dire si vous perdez sur le prix, face à un concurrent ou faute de décision.", decision: "ce mois-ci, six raisons de perte au maximum, les cases fourre-tout retirées, champ obligatoire pour fermer un deal.", worthLabel: "Ce que ça change", worth: "dans trois mois, vous saurez sur quoi vous perdez. Aujourd’hui, vous devinez.",
        unknown: "ce que vos clients perdus diraient eux-mêmes. Ce n’est dans aucun fichier.",
        sol: { name: "Six raisons de perte, obligatoires, vérifiées auprès des clients", w2: "La liste à installer", rule: "Six raisons qui appellent chacune une action différente : le client n’a rien décidé ; un concurrent a gagné ; le prix ; pas le bon moment ; mauvaise cible, ce deal n’aurait pas dû entrer ; plus de réponse. Plus une ligne libre pour le détail.",
          ritual: "Chaque mois, appelez cinq clients perdus. La raison que donne le client et celle saisie par le commercial coïncident rarement : c’est là que vous apprenez quelque chose.", sign: "dans trois mois, moins d’une perte sur dix sans raison. Aujourd’hui : " + W10[xv] + " sur dix." },
        slide: "La raison de perte devient obligatoire, sur une liste de six : aujourd’hui, " + W10[xv] + " pertes sur dix n’ont pas d’explication." }); }
    else if (d8 && silent) { var ss = pc(silent.n, lost.length), frac = ss >= 45 ? "Près d’un deal perdu sur deux meurt" : ss >= 30 ? "Un deal perdu sur trois meurt" : ss >= 22 ? "Plus d’un deal perdu sur quatre meurt" : ss >= 17 ? "Un deal perdu sur cinq meurt" : fmt.pct(ss) + " de vos deals perdus meurent";
      B.push({ key: "reasons", ch: 2, tone: "r", read: "B", audit: auditR, title: frac + " en silence.", sub: qt(silent.name) + " veut dire chez vous que le prospect a cessé de répondre : " + fmt.pct(ss) + " de vos pertes. Il reste " + fmt.pct(d8.share) + " de pertes sans aucune raison.", truths: rT,
        body: "Le sujet n’est plus la case, c’est la relance.", decision: "ce mois-ci, fixez combien de relances avant de fermer un deal, et à quel rythme.", unknown: "à quel moment vos prospects décrochent, et après combien de relances.",
        sol: { name: "Une relance qui a une fin, et un prochain rendez-vous toujours daté", rule: "Par exemple cinq relances en trois semaines, par e-mail et par téléphone, puis un dernier message qui annonce que vous fermez le dossier. Le nombre exact compte moins que le fait d’en fixer un. Ensuite le deal est fermé, et pourra être rouvert.",
          ritual: "Un prospect qui se tait après une proposition a plus souvent peur de se tromper qu’il n’a perdu l’intérêt. Réduisez son risque au lieu de relancer plus fort : une seule recommandation plutôt que trois options, un démarrage limité, une porte de sortie. Et ne quittez jamais un rendez-vous sans la date du suivant.", sign: "la part de deals perdus en silence baisse. Aujourd’hui : " + fmt.pct(ss) + "." },
        slide: "Nous fixons une règle de relance : " + frac.charAt(0).toLowerCase() + frac.slice(1) + " en silence." }); }
    else if (d8) B.push({ key: "reasons", ch: 2, tone: "g", read: "C", audit: auditR, title: "Vous savez pourquoi vous perdez : " + W10[10 - x10(d8.share)] + " pertes sur dix ont une vraie raison.", sub: M.reasons.slice(0, 3).map(function (x) { return x.name + " (" + fmt.pct(pc(x.n, lost.length)) + ")"; }).join(", ") + " arrivent en tête.", truths: rT });
    var A = [];
    A.push(shareSt >= 15 && nSt >= 3 ? { q: "Puis-je croire mon pipeline ?", a: (shareSt >= 30 ? "Non. " : "Pas entièrement. ") + fmt.eur(M.pipe.union) + " sur " + fmt.eur(openEur) + " de pipeline ouvert sont à l’arrêt.", tone: shareSt >= 30 ? "r" : "o" } : { q: "Puis-je croire mon pipeline ?", a: "Oui. " + (nSt ? (nSt > 1 ? "Seuls " + nSt + " deals sont" : "Un seul deal est") + " à l’arrêt." : "Aucun deal n’est à l’arrêt."), tone: "g" });
    A.push(b6c && b6c.status === "r" ? { q: "Où est-ce que je perds ?", a: "En fin de parcours : " + fmt.int(b6c.lateN) + " deals déjà perdus en " + lateA + " ou en " + lateB + ".", tone: "r" } : S >= 2 ? { q: "Où est-ce que je perds ?", a: M.leak ? "Surtout à l’étape " + M.leak + "." : "Nulle part en particulier : vos pertes sont réparties sur tout le parcours.", tone: M.leak ? "o" : "g" } : { q: "Où est-ce que je perds ?", a: "Votre fichier ne le dit pas : il manque les dates de passage d’étape.", tone: "na" });
    A.push(!d8 ? { q: "Est-ce que je sais pourquoi ?", a: "Votre fichier ne contient pas assez de raisons de perte pour le dire.", tone: "na" } : d8.status === "r" ? { q: "Est-ce que je sais pourquoi ?", a: "Non. " + x10(d8.share) + " pertes sur 10 n’ont pas de raison.", tone: "r" } : silent ? { q: "Est-ce que je sais pourquoi ?", a: "Oui, et c’est le silence : " + fmt.pct(pc(silent.n, lost.length)) + " de vos deals perdus ne répondent plus.", tone: "o" } : { q: "Est-ce que je sais pourquoi ?", a: "Oui. " + (10 - x10(d8.share)) + " pertes sur 10 ont une vraie raison.", tone: "g" });
    var okLine = k2 != null && k2 >= wrMin ? "vous signez " + fmt.pct(k2) + " de vos deals sérieux, c’est " + (k2 > wrMax ? "au-dessus de" : "dans") + " la norme (" + wrMin + " à " + wrMax + NB + "%)." + (b6c && b6c.status === "r" ? " Le problème n’est pas l’entrée du pipeline, c’est la fin." : "") : M.good[0] ? M.good[0].text.charAt(0).toLowerCase() + M.good[0].text.slice(1) : "";
    var V = shareSt >= 15 && nSt >= 3 ? { kind: "alive", title: "Votre CRM affiche " + fmt.eur(openEur) + ". " + fmt.eur(alive) + " sont encore vivants.", em: fmt.eur(alive), sub: nSt + " deals ne bougent plus ou devaient signer à une date déjà passée. Si votre prévision part de " + fmt.eur(openEur) + ", " + fmt.pct(shareSt) + " reposent sur eux.", bench: shareSt >= 33 ? "Au-delà de 30" + NB + "% de pipeline à l’arrêt, on ne peut plus s’appuyer dessus pour prévoir." : "" }
      : b6c && b6c.status === "r" ? { kind: "leak", title: "Votre pipeline de " + fmt.eur(openEur) + " tient debout. C’est en fin de parcours que vous perdez : " + fmt.int(b6c.lateN) + " deals.", em: fmt.int(b6c.lateN) + " deals", sub: fmt.pct(b6c.share) + " de vos pertes arrivent en " + lateA + " ou en " + lateB + ", une fois tout le travail fait.", bench: "" }
      : d8 && d8.status === "r" ? { kind: "why", title: "Votre pipeline de " + fmt.eur(openEur) + " tient debout. Mais " + W10[x10(d8.share)] + " fois sur dix, vous ne savez pas pourquoi vous perdez.", em: W10[x10(d8.share)] + " fois sur dix", sub: "Vos raisons de perte ne disent rien : difficile de corriger ce qu’on ne nomme pas.", bench: "" }
      : { kind: "ok", title: "Votre pipeline de " + fmt.eur(openEur) + " tient debout, et rien d’urgent ne ressort.", em: fmt.eur(openEur), sub: (nSt ? nSt + " deals sur " + open.length + " sont à l’arrêt" : "Aucun deal n’est à l’arrêt") + ". Le détail est plus bas, sujet par sujet.", bench: "" };
    // a solution is always three moves: the first gesture (the decision of the slide), the rule to install, the ritual that makes it last
    B.forEach(function (b) { if (b.sol) b.sol.steps = [{ w: "Pour commencer", t: cap(b.decision) + (b.sol.start ? " " + b.sol.start : "") }, { w: b.sol.w2 || "La règle à installer", t: b.sol.rule }, { w: "Pour que ça tienne", t: b.sol.ritual }]; });
    // the slide and the roadmap follow the same priority, whatever the order of the chapters
    var PRI = ["stalled", "journey", "reasons", "orphans", "amounts", "dates", "rep"], ranked = B.slice().sort(function (a, b) { return PRI.indexOf(a.key) - PRI.indexOf(b.key); });
    M.story = { verdict: V, answers: A, good: okLine, blocks: B, decisions: ranked.filter(function (b) { return b.slide; }).slice(0, 3).map(function (b) { return b.slide; }), roadmap: ranked.filter(function (b) { return b.sol; }).map(function (b) { return { key: b.key, name: b.sol.name, first: cap(b.decision) }; }), slideTitle: V.kind === "alive" ? "Notre pipeline vivant : " + fmt.eur(alive) + ", pas " + fmt.eur(openEur) + "." : "Notre pipeline : " + fmt.eur(openEur) + ". Voici où nous perdons.", alive: alive, aliveShare: 100 - shareSt, aliveN: open.length - nSt };
    // ---------- read at a glance: for every finding a short form (figure, one line), the action in one line, and the method behind the number ----------
    var defLim = sd || (S ? Math.round(mult * (med(k5.filter(Boolean)) || 0)) || 30 : k4 ? Math.round(mult * k4) : 60), inStage = S ? "dans la même étape" : "sans signature";
    B.forEach(function (b) {
      var k = b.key, x = null;
      b.sev = b.tone === "r" ? "Constat critique" : b.tone === "o" ? "Question" : b.tone === "g" ? "Sain" : "Non mesurable";
      if (b.tone !== "r") return;
      if (k === "stalled") x = { big: nSt + " deals à l’arrêt", fig: fmt.eur(M.pipe.union), line: fmt.pct(shareSt) + " du montant de votre pipeline ouvert", rule: "stale",
        method: "Deals ouverts qui dépassent la durée limite ci-dessous, ou dont la date de signature prévue est passée.", scope: nSt + " deals sur " + open.length + " ouverts · " + fmt.eur(M.pipe.union) + " sur " + fmt.eur(openEur),
        act: "Relancer ou fermer ces " + nSt + " deals, puis fixer une durée limite " + (S ? "par étape" : "par deal"), goal: "moins de 15" + NB + "% du pipeline à l’arrêt", now: fmt.pct(shareSt),
        s: ["Chaque commercial relance ou ferme ses deals à l’arrêt, d’ici vendredi", "Une alerte dans le CRM quand un deal dépasse sa durée limite", "Une revue de pipeline limitée aux deals en alerte"] };
      else if (k === "orphans") x = { big: byC.E8.orphN + " deals sans porteur", fig: fmt.eur(byC.E8.impact), line: "Ils sont confiés à quelqu’un qui ne vend plus chez vous", rule: "team",
        method: "Deals ouverts dont le commercial fait partie des personnes que vous avez déclarées comme ne vendant plus.", scope: byC.E8.orphN + " deals sur " + open.length + " ouverts · " + fmt.eur(byC.E8.impact),
        act: "Réattribuer ou fermer ces " + byC.E8.orphN + " deals cette semaine", goal: "aucun deal ouvert sans porteur", now: byC.E8.orphN + " deals",
        s: ["Réattribuer ces deals à un porteur nommé, les plus avancés d’abord", "Aucun compte désactivé tant que ses deals n’ont pas de nouveau porteur", "Le nouveau porteur appelle chaque client dans les sept jours"] };
      else if (k === "amounts") x = { big: (nPh >= 3 ? nPh + " deals" : fmt.pct(modeAllShare) + " des deals") + " à " + modeTxt + " pile", fig: nPh >= 3 ? ePh : "", line: "Le même montant sur tous ces deals, sans chiffrage propre", rule: "fixed",
        method: "Deals qui portent exactement le même montant. Au-delà d’un deal sur dix, c’est un tarif ou une valeur remplie d’office.", scope: fmt.pct(modeAllShare) + " des " + fmt.int(withAmt.length) + " deals chiffrés" + (nPh >= 3 ? " · " + nPh + " ouverts, " + ePh : ""),
        act: "Faire chiffrer ces deals, et supprimer le montant par défaut", goal: "aucun montant porté par plus d’un deal sur dix", now: fmt.pct(modeAllShare),
        s: ["Faire chiffrer ces deals par ceux qui les portent, cette semaine", "Plus de valeur par défaut : le montant devient obligatoire " + (serious ? "à partir de " + qt(serious) : "quand le deal est sérieux"), "Une fourchette plutôt qu’un chiffre inventé"] };
      else if (k === "dates") x = { big: fmt.pct(h3) + " des dates au dernier jour du mois", fig: "", line: "Ces dates ne viennent pas d’un engagement du client", rule: "eom",
        method: "Part des deals ouverts dont la date de signature prévue tombe le dernier jour d’un mois.", scope: fmt.pct(h3) + " des " + withClose.length + " deals ouverts datés",
        act: "N’accepter qu’une date de signature donnée par le client", goal: "moins d’une date sur cinq en fin de mois", now: fmt.pct(h3),
        s: ["Une date de signature vient du client, sinon le deal n’en a pas", "Un champ court « ce qui justifie cette date », obligatoire", "Chaque semaine, regarder les dates repoussées"] };
      else if (k === "journey") x = { big: fmt.int(b6c.lateN) + " deals perdus en fin de parcours", fig: fmt.eur(b6c.lateEur), line: fmt.pct(b6c.share) + " de vos pertes, en " + lateA + " ou en " + lateB, rule: null,
        method: "Pour chaque deal perdu, la dernière étape atteinte. La fin de parcours, ce sont les deux dernières étapes.", scope: fmt.int(b6c.lateN) + " deals sur " + fmt.int(cl.length) + " perdus" + (cohort !== deals ? ", parmi les deals créés il y a plus de quatre mois" : "") + " · " + fmt.eur(b6c.lateEur),
        act: "Fixer trois conditions d’entrée en " + lateA + ", vérifiables côté client", goal: "moins d’une perte sur deux en fin de parcours", now: fmt.pct(b6c.share), gain: "+" + b6c.gainN + " deals gagnés, soit " + fmt.eur(b6c.gainEur),
        s: ["Pendant un mois, votre feu vert avant toute entrée en " + lateA, "Trois conditions d’entrée, chacune étant un acte du client", "Relire les dix derniers deals perdus tard"] };
      else if (k === "rep") x = { big: fmt.pct(e2c.conv) + " contre " + fmt.pct(e2c.team) + " en " + e2c.stageName, fig: "", line: "Un commercial décroche de l’équipe à cette étape, et seulement là", rule: "team",
        method: "Pour chaque commercial et chaque étape, la part de ses deals qui passent à la suite, comparée à l’équipe. Alerte sous 70" + NB + "% du niveau de l’équipe.", scope: fmt.pct(e2c.conv) + " sur " + e2c.n + " deals, contre " + fmt.pct(e2c.team) + " pour l’équipe",
        act: "Accompagner ce commercial sur l’étape " + e2c.stageName + ", et elle seule", goal: "rejoindre l’équipe à cette étape : " + fmt.pct(e2c.team), now: fmt.pct(e2c.conv), gain: "+" + e2c.gainN + " deals gagnés",
        s: ["Relire ensemble ses 5 derniers deals perdus à cette étape", "Les comparer à deux deals gagnés par un collègue", "Deux rendez-vous observés, un objectif à trente jours"] };
      else if (k === "reasons" && b.read === "A") x = { big: x10(d8.share) + " pertes sur 10 sans raison", fig: fmt.eur(d8.impact), line: "Impossible de savoir sur quoi vous perdez", rule: rT[0] || null,
        method: "Part des deals perdus dont la raison est vide, ou ne dit pas pourquoi le deal est perdu.", scope: fmt.pct(d8.share) + " des " + fmt.int(lost.length) + " deals perdus · " + fmt.eur(d8.impact),
        act: "Imposer six raisons de perte, obligatoires pour fermer un deal", goal: "moins d’une perte sur dix sans raison", now: fmt.pct(d8.share),
        s: ["Six raisons au maximum, obligatoires pour fermer un deal", "Des raisons qui appellent chacune une action différente", "Cinq clients perdus appelés chaque mois"] };
      else if (k === "reasons") x = { big: fmt.pct(pc(silent.n, lost.length)) + " des deals perdus en silence", fig: fmt.eur(silent.eur), line: "Le prospect a cessé de répondre", rule: rT[0] || null,
        method: "Part des deals perdus classés " + qt(silent.name) + " : vous m’avez dit que cela veut dire que le prospect ne répond plus.", scope: silent.n + " deals sur " + fmt.int(lost.length) + " perdus · " + fmt.eur(silent.eur),
        act: "Fixer un nombre de relances, puis fermer le deal", goal: "moins de deals perdus en silence", now: fmt.pct(pc(silent.n, lost.length)),
        s: ["Fixer combien de relances avant de fermer, et à quel rythme", "Un dernier message qui annonce la fermeture du dossier", "Jamais de rendez-vous sans la date du suivant"] };
      if (!x) return;
      b.big = x.big; b.fig = x.fig; b.line = x.line; b.method = x.method; b.scope = x.scope; b.rule = x.rule;
      b.sol.act = x.act; b.sol.goal = x.goal; b.sol.now = x.now; b.sol.gain = x.gain || ""; b.sol.steps.forEach(function (st, i) { st.s = x.s[i]; });
    });
    V.method = V.kind === "alive" ? "Pipeline ouvert, moins les deals à l’arrêt et ceux dont la date de signature prévue est passée." : "Montant total des deals ouverts de votre fichier."; V.scope = open.length + " deals ouverts, " + fmt.eur(openEur) + (nSt ? ". À l’arrêt : " + nSt + " deals, " + fmt.eur(M.pipe.union) + " (sans mouvement " + fmt.eur(M.pipe.stagOnly) + ", date dépassée " + fmt.eur(M.pipe.pastOnly) + ", les deux à la fois " + fmt.eur(M.pipe.both) + ")" : ""); V.rule = tOf("stale") ? "stale" : null;
    M.story.glance = A.map(function (a, i) { var bs = B.filter(function (b) { return b.ch === i; }), top = bs.filter(function (b) { return b.sol; })[0], ask = bs.filter(function (b) { return b.tone === "o"; })[0]; return { q: a.q, a: a.a, tone: a.tone, key: top ? top.key : ask ? ask.key : bs[0] ? bs[0].key : "", act: top ? top.sol.act : "", goal: top ? top.sol.goal : "", pending: !top && ask ? ask.title : "" }; });
    M.story.counts = { crit: B.filter(function (b) { return b.tone === "r"; }).length, ask: B.filter(function (b) { return b.tone === "o"; }).length, ok: B.filter(function (b) { return b.tone === "g"; }).length };
    // the sentence that restates each rule: "Modifier la règle" puts it in the rule bar, ready to be changed
    T.forEach(function (t) {
      t.say = t.id === "stale" ? "Un deal est à l’arrêt après " + defLim + " jours " + inStage : t.id === "fixed" ? fmt.int(+modeAll) + " € est un prix de notre catalogue" : t.id === "eom" ? "Dater à fin de mois est notre règle"
        : t.id.indexOf("reason:") === 0 ? "« " + t.id.slice(7) + " » veut dire que le prospect ne répond plus" : t.id === "qual" ? "Le taux de signature se calcule à partir de l’étape " + stages[Math.min(qs, S - 1)]
        : t.id === "cycle" ? "Chez nous, une vente dure " + alertDays + " jours" : t.id === "since" ? "Jugez seulement les 12 derniers mois" : "";
    });
    // three starting points for the rule bar, shown only when it has focus: a rule, a calculation method, an indicator
    M.hints = [{ kind: "Règle", text: "Un deal sans nouvelle depuis 45 jours est à l’arrêt" },
      S >= 3 ? { kind: "Calcul", text: "Le taux de signature se calcule à partir de l’étape " + stages[Math.min(2, S - 1)] } : { kind: "Calcul", text: "Ne comptez pas les deals de moins de 1 000 €" },
      { kind: "KPI", text: dims.some(function (dm) { return dm.key === "source"; }) ? "Panier moyen des deals gagnés, par source" : "Nombre de deals créés par mois" }];
    // how each secondary check is computed, in one sentence (shown on hover)
    var HOW = { A1: "Nombre d’étapes ouvertes de votre pipeline. Entre quatre et sept, il reste lisible.", A2: "Part des deals ouverts rangés dans l’étape la plus chargée.", A3: "Part des deals clos qui n’ont aucune date d’entrée dans au moins une étape de leur parcours.", A4: "Part des deals qui passent chaque étape. Au-delà de 95" + NB + "%, l’étape ne filtre rien.", A6: "Part des deals dont la première étape renseignée n’est pas la première du pipeline.",
      B1: "Pour chaque étape, la part des deals qui passent et le montant perdu à ce stade.", B2: "Deals gagnés divisés par les deals gagnés ou perdus, parmi ceux qui ont atteint l’étape où un deal est sérieux.", B3: "Le même taux calculé en montant, comparé au taux en nombre de deals.", B4: "Deals créés par semaine sur les quatre dernières semaines, comparés aux douze précédentes.", B5: "Taux de signature de chaque source ayant au moins dix deals clos.", B6: "Part des deals perdus dont la dernière étape atteinte est l’une des deux dernières.",
      C1: "Durée entre la création et la signature du deal gagné du milieu, sur douze mois, comparée à la durée attendue.", C2: "Part de la durée totale d’une vente passée dans chaque étape.", C3: "Montant des deals ouverts restés dans leur étape au-delà de la durée limite, rapporté au pipeline ouvert.", C4: "Part des deals ouverts plus vieux que deux fois la durée d’une vente gagnée.",
      D1: "Part des deals ouverts sans montant, sans date de signature, sans commercial ou sans source : le pire des quatre.", D2: "Part des deals ouverts dont la date de signature prévue est déjà passée.", D5: "Part des deals ouverts sans échange enregistré récemment.", D6: "Part des deals qui portent exactement le même montant, hors tarifs que vous avez déclarés.", D7: "Part des entreprises qui ont plusieurs deals ouverts en même temps.", D8: "Part des deals perdus dont la raison est vide ou ne dit rien.",
      E1: "Écart de taux de signature entre les commerciaux ayant au moins quinze deals clos.", E2: "Pour chaque commercial et chaque étape, la part de ses deals qui passent, comparée à l’équipe.", E4: "Part du montant gagné réalisée par le cinquième des commerciaux qui signe le plus.", E8: "Deals ouverts portés par une personne que vous avez déclarée comme ne vendant plus.",
      G2: "Part des deals perdus dès les deux premières étapes. Perdre tôt coûte moins cher.", G4: "Parmi les pertes qui ont une vraie raison, la part de celles où le client n’a rien décidé.", G6: "Part des deals gagnés en moins de sept jours après leur création.", H2: "Part des deals gagnés signés dans les cinq derniers jours ouvrés du mois.", H3: "Part des dates de signature prévues qui tombent le dernier jour d’un mois.", I1: "Taux de signature de chaque segment ayant au moins dix deals clos.", P1: "Montant des deals à l’arrêt ou à date de signature dépassée, rapporté au pipeline ouvert." };
    M.checks.forEach(function (c) { c.how = (HOW[c.id] || "") + (c.n != null && c.status !== "na" ? " Calculé sur " + fmt.int(c.n) + " deals." : ""); });
    // ---------- indicators the user invented in plain words (cfg.kpis): a measure, a population, filters, a breakdown ----------
    var MOIS = ["janv.", "févr.", "mars", "avr.", "mai", "juin", "juil.", "août", "sept.", "oct.", "nov.", "déc."], POPS = { all: deals, open: open, won: won, lost: lost, closed: won.concat(lost) };
    var kpiOf = function (k) {
      var f = k.filters || {}, base = POPS[k.pop] || deals, sIx = f.stage != null ? stageIx[f.stage] : null, hasF = Object.keys(f).length > 0;
      var keepD = function (d) { return !(f.min != null && !(d.amount >= f.min)) && !(f.max != null && !(d.amount != null && d.amount <= f.max)) && !(f.dim && norm(dimOf(d, f.dim.key)) !== norm(f.dim.value)) && !(f.owner && d.owner !== f.owner) && !(f.reason && norm(d.reason) !== norm(f.reason)) && !(sIx != null && (d.status === "open" ? d.cur : d.maxStage) !== sIx) && !(f.since && d.created < snap - f.since * 30.4 * DAY); };
      var fv = function (v) { return v == null ? "—" : k.measure === "count" ? fmt.int(v) : k.measure === "winrate" || k.measure === "share" ? fmt.pct(v) : k.measure === "cycle" || k.measure === "stagetime" ? fmt.days(v) : fmt.eur(v); };
      var val = function (a) {
        var wa = a.filter(function (d) { return d.amount > 0; }), cy;
        if (k.measure === "count") return { v: a.length, n: a.length };
        if (k.measure === "sum") return { v: sum(a, amt), n: a.length };
        if (k.measure === "avg") return { v: wa.length ? sum(wa, amt) / wa.length : null, n: wa.length };
        if (k.measure === "median") return { v: med(wa.map(amt)), n: wa.length };
        if (k.measure === "winrate") { a = a.filter(function (d) { return S < 2 || reached(d, Math.min(qs, S - 1)); }); return { v: pc(a.filter(function (d) { return d.status === "won"; }).length, a.length), n: a.length }; }
        if (k.measure === "cycle") { cy = a.map(function (d) { return d.cycle; }).filter(function (c) { return c != null; }); return { v: !cy.length ? null : k.stat === "avg" ? sum(cy) / cy.length : med(cy), n: cy.length }; }
        if (k.measure === "weighted") return { v: sum(a, function (d) { return amt(d) * ((k.weights || {})[norm(stages[d.cur] || "")] || 0) / 100; }), n: a.length };
        return { v: null, n: 0 };
      };
      var gk = function (d) { var b = k.by; return b === "owner" ? d.owner || "" : b === "stage" ? (d.status === "open" ? stages[d.cur] : stages[d.maxStage]) || d.stage || "—" : b === "reason" ? d.reason || "Non renseigné" : b === "month" ? String(mKey(k.pop === "all" || k.pop === "open" ? d.created : d.closed || d.created)) : dimOf(d, b) || "Non renseigné"; };
      var pop = base.filter(keepD), den = hasF ? base : deals, share = k.measure === "share", tot, rows = [], more = 0;
      if (k.measure === "stagetime") { var fi = stageIx[k.stage]; tot = { v: fi != null && M.funnel[fi] ? M.funnel[fi].days : null, n: fi != null && M.funnel[fi] ? M.funnel[fi].reached : 0 }; rows = M.funnel.map(function (s) { return { key: s.name, l: s.name, who: null, v: s.days, n: s.reached, f: fv(s.days) }; }).filter(function (r) { return r.v != null; }); }
      else {
        tot = share ? { v: pc(pop.length, den.length), n: den.length } : val(pop);
        if (k.by) {
          var g = groupBy(share ? den : pop, gk);
          rows = Object.keys(g).map(function (key) { var r = share ? { v: pc(g[key].filter(keepD).length, g[key].length), n: g[key].length } : val(g[key]); return { key: key, l: k.by === "month" ? MOIS[+key % 12] + NB + String(Math.floor(+key / 12)).slice(2) : k.by === "owner" ? "" : key, who: k.by === "owner" ? key : null, v: r.v, n: r.n, f: fv(r.v) }; }).filter(function (r) { return r.v != null && r.n > 0; });
          if (k.by === "month") rows = rows.sort(function (a, b) { return a.key - b.key; }).slice(-12);
          else if (k.by === "stage") rows.sort(function (a, b) { var ia = stageIx[norm(a.key)], ib = stageIx[norm(b.key)]; return (ia != null ? ia : 99) - (ib != null ? ib : 99); });
          else { rows.sort(function (a, b) { return b.v - a.v; }); more = Math.max(0, rows.length - 8); rows = rows.slice(0, 8); }
        }
      }
      var HK = { count: "Nombre de deals correspondant à votre description", sum: "Somme des montants des deals correspondant à votre description", avg: "Moyenne des montants, sur les deals qui en ont un", median: "Montant du deal du milieu, quand on les range du plus petit au plus gros", winrate: "Deals gagnés divisés par les deals gagnés ou perdus" + (S >= 2 ? ", parmi ceux arrivés à l’étape où un deal est sérieux" : ""), cycle: (k.stat === "avg" ? "Durée moyenne" : "Durée du deal du milieu") + " entre la création et la signature des deals gagnés", share: "Deals concernés divisés par " + (hasF ? "tous les deals de la même famille" : "tous les deals"), weighted: "Montant de chaque deal ouvert multiplié par la probabilité que vous donnez à son étape", stagetime: "Durée entre l’entrée dans l’étape et l’entrée dans la suivante, pour le deal du milieu" };
      return { id: k.id, label: k.label, text: k.text, measure: k.measure, by: k.by || null, value: tot.v, f: fv(tot.v), n: tot.n, rows: rows, more: more, how: HK[k.measure] + ".", scope: "Calculé sur " + fmt.int(tot.n) + " deals, avec vos règles" };
    };
    M.custom = (cfg.kpis || []).map(kpiOf);
    // ---------- the sales cycle from the first stage to the signature: deals entering each stage, share moving on, time spent ----------
    var weak = -1; M.funnel.forEach(function (f, i) { if (f.conv != null && (weak < 0 || f.conv < M.funnel[weak].conv)) weak = i; });
    M.cycle = !S ? null : { stages: M.funnel.map(function (f) { return { name: f.name, n: f.reached, conv: f.conv, days: f.days }; }), from: M.funnel[0].reached, won: cw.length, overall: pc(cw.length, M.funnel[0].reached), days: k4, weak: weak, slow: slow,
      method: "Pour chaque étape : les deals qui y entrent, la part qui passe à la suivante, et le temps qu’y reste le deal du milieu.", scope: fmt.int(cohort.length) + " deals" + (cohort !== deals ? " créés il y a plus de quatre mois, pour que leur parcours soit terminé" : "") };
    // compact anonymised snapshot of the analysed pipeline, kept by the app to compare with the next export
    var idOk = deals.length && deals.every(function (d) { return d.id; }) && Object.keys(groupBy(deals, function (d) { return d.id; })).length === deals.length;
    M.snapshot = idOk ? { date: snap, stages: stages, deals: deals.map(function (d) { return [String(d.id), d.cur, d.status === "won" ? 1 : d.status === "lost" ? 2 : 0, d.amount || 0, d.close || 0, d.owner]; }) } : null;
    M.meta = { rows: deals.length, open: open.length, won: won.length, lost: lost.length, months: Math.round((snap - Math.min.apply(null, deals.map(function (d) { return d.created; }))) / DAY / 30.4), reps: codes.length, cohort: cohort.length, executed: M.checks.filter(function (c) { return c.status !== "na" && !c.pattern; }).length };
    return M;
  }

  // ---------- 5. business rules: apply a patch, undo it, read a rule said in plain words ----------
  var CLS = { vague: "c’est une case par défaut, qui ne dit pas pourquoi", nd: "le prospect ne répond plus", comp: "un concurrent a gagné", price: "le prix a bloqué", other: "c’est une vraie raison de perte" };
  function applyRule(cfg, set) {
    for (var k in set) {
      if (k === "reasons" || k === "stageDays") { cfg[k] = cfg[k] || {}; for (var r in set[k]) { if (set[k][r] == null) delete cfg[k][r]; else cfg[k][r] = set[k][r]; } }
      else if (k === "addFixed") cfg.fixedAmounts = (cfg.fixedAmounts || []).filter(function (v) { return v !== set.addFixed; }).concat([set.addFixed]);
      else if (k === "removeFixed") cfg.fixedAmounts = (cfg.fixedAmounts || []).filter(function (v) { return v !== set.removeFixed; });
      else if (k === "addExclude") cfg.exclude = (cfg.exclude || []).filter(function (x) { return !(x.key === set.addExclude.key && x.value === set.addExclude.value); }).concat([set.addExclude]);
      else if (k === "toggleExclude") { var te = set.toggleExclude, same = function (x) { return x.key === te.key && x.value === te.value; }, had = (cfg.exclude || []).some(same); cfg.exclude = (cfg.exclude || []).filter(function (x) { return !same(x); }); if (!had) cfg.exclude.push(te); }
      else if (k === "toggleOwner") { var hadO = (cfg.ownersOff || []).indexOf(set.toggleOwner) >= 0; cfg.ownersOff = (cfg.ownersOff || []).filter(function (h) { return h !== set.toggleOwner; }); if (!hadO) cfg.ownersOff.push(set.toggleOwner); }
      else if (k === "ownerOff") cfg.ownersOff = (cfg.ownersOff || []).filter(function (h) { return h !== set.ownerOff; }).concat([set.ownerOff]);
      else if (k === "ownerOn") cfg.ownersOff = (cfg.ownersOff || []).filter(function (h) { return h !== set.ownerOn; });
      else if (k === "addKpi") cfg.kpis = (cfg.kpis || []).filter(function (x) { return x.id !== set.addKpi.id; }).concat([set.addKpi]);
      else if (k === "removeKpi") cfg.kpis = (cfg.kpis || []).filter(function (x) { return x.id !== set.removeKpi; });
      else cfg[k] = set[k];
    }
    return cfg;
  }
  // the patch that puts back what `set` is about to change: used to withdraw a rule the user said in plain words
  function inverse(cfg, set) {
    var u = {}, k;
    for (k in set) {
      if (k === "reasons" || k === "stageDays") { u[k] = {}; for (var r in set[k]) u[k][r] = cfg[k] && cfg[k][r] != null ? cfg[k][r] : null; }
      else if (k === "addFixed") { if ((cfg.fixedAmounts || []).indexOf(set[k]) < 0) u.removeFixed = set[k]; }
      else if (k === "removeFixed") { if ((cfg.fixedAmounts || []).indexOf(set[k]) >= 0) u.addFixed = set[k]; }
      else if (k === "addExclude" || k === "toggleExclude") { var x = set[k], had = (cfg.exclude || []).some(function (y) { return y.key === x.key && y.value === x.value; }); if (k === "toggleExclude" || !had) u.toggleExclude = x; }
      else if (k === "toggleOwner") u.toggleOwner = set[k];
      else if (k === "ownerOff") { if ((cfg.ownersOff || []).indexOf(set[k]) < 0) u.ownerOn = set[k]; }
      else if (k === "ownerOn") { if ((cfg.ownersOff || []).indexOf(set[k]) >= 0) u.ownerOff = set[k]; }
      else if (k === "addKpi") { var kid = set[k].id; if (!(cfg.kpis || []).some(function (y) { return y.id === kid; })) u.removeKpi = kid; }
      else u[k] = cfg[k] != null ? cfg[k] : null;
    }
    return u;
  }

  // A business rule said in plain French becomes a rule of calculation. Deterministic reading, no LLM: nothing leaves the browser.
  // What is recognised comes back with the patch to apply and the truths it answers; the rest comes back as notes, with no effect on the numbers.
  // ctx.names (owner hash → clear name) only exists in the user's browser: it lets "Julie ne vend plus" find its person.
  var NUMW = { un: 1, une: 1, deux: 2, trois: 3, quatre: 4, cinq: 5, six: 6, sept: 7, huit: 8, neuf: 9, dix: 10, douze: 12, quinze: 15, vingt: 20, trente: 30 }, NUMS = Object.keys(NUMW).join("|"), UNITS = "jours?|j|semaines?|mois|ans?|annees?";
  var DUR = new RegExp("(\\d+)\\s*(" + UNITS + ")\\b"), rxEsc = function (s) { return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"); };
  function interpret(text, M, ctx) {
    var names = (ctx && ctx.names) || {}, out = { understood: [], notes: [] }, N2 = M.funnel.length > 0, qt = function (s) { return "«" + NB + s + NB + "»"; };
    var optOf = function (id, set) { var t = M.truths.filter(function (x) { return x.id === id; })[0]; if (!t) return null; var s = JSON.stringify(set); for (var i = 0; i < t.options.length; i++) if (JSON.stringify(t.options[i].set) === s) return i; return true; };
    var days = function (m) { return Math.round(+m[1] * (/^s/.test(m[2]) ? 7 : /^m/.test(m[2]) ? 30 : /^a/.test(m[2]) ? 365 : 1)); };
    var months = function (m) { return Math.round(+m[1] * (/^a/.test(m[2]) ? 12 : 1)); };
    var has = function (n, w) { return w.length > 1 && (" " + n + " ").indexOf(" " + w) >= 0; };   // word-prefix match: "partenaire" also finds "partenaires"
    var hasW = function (n, w) { return w.length > 1 && new RegExp("(^| )" + rxEsc(w) + "s?( |$)").test(n); };   // whole word, plural allowed
    var money = function (o) { var m = o.match(/(\d[\d\s .,]*)\s*(k€|k\b|€|euros?|eur\b)/i); if (!m) return null; var raw = m[1].replace(/[\s ]/g, ""); if (/^\d{1,3}(\.\d{3})+$/.test(raw)) raw = raw.replace(/\./g, ""); var v = parseFloat(raw.replace(",", ".")) * (/k/i.test(m[2]) ? 1000 : 1); return v > 0 ? v : null; };
    // An indicator described in plain words: a measure, a population, optional filters and a breakdown ("par source").
    var GROUPS = [["owner", /par (commercial|commerciaux|vendeur|personne|responsable|porteur|proprietaire)/], ["stage", /par (etape|phase|stade)/], ["month", /par mois|mensuel|chaque mois/], ["reason", /par (raison|motif)/], ["source", /par (source|origine|canal|provenance)/], ["segment", /par (segment|taille|secteur)/]];
    var BYTXT = { owner: "par commercial", stage: "par étape", month: "par mois", reason: "par raison de perte" }, dimOfKey = function (key) { return (M.dims || []).filter(function (d) { return d.key === key; })[0]; };
    var readKpi = function (o, n, stageHit) {
      var f = {}, w = {}, by = null, m;
      if (/ponder/.test(n) && N2) {
        M.stages.forEach(function (st) { var sn = norm(st), a = n.match(new RegExp("(\\d{1,3}) (?:en |pour |sur |a l etape )?" + rxEsc(sn) + "( |$)")) || n.match(new RegExp(rxEsc(sn) + " (?:a |de )?(\\d{1,3})( |$)")); if (a && +a[1] <= 100) w[sn] = +a[1]; });
        if (Object.keys(w).length >= 2) return { id: "k:pondere", measure: "weighted", pop: "open", filters: {}, weights: w, by: "stage", text: o, label: "Pipeline pondéré par la probabilité de chaque étape" };
      }
      var meas = /(taux de (?:signature|closing|conversion|transformation|reussite|gain|victoire)|win rate)/.test(n) ? "winrate"
        : stageHit >= 0 && N2 && /(temps|duree|delai)\w* (?:passe |moyen |moyenne |median |mediane )?(?:en|dans|a l etape)/.test(n) ? "stagetime"
        : /(duree|cycle|delai)/.test(n) && /(vente|signature|signer|cycle|conclu|gagn)/.test(n) ? "cycle"
        : /(panier|ticket)/.test(n) || /(montant|valeur|taille)\w* (?:moyen|median)/.test(n) || /(moyenne|mediane) des montants/.test(n) ? (/median/.test(n) ? "median" : "avg")
        : /(\bpart\b|proportion|pourcentage)/.test(n) ? "share"
        : /(montant|valeur|chiffre d affaires|\bca\b|total|somme)/.test(n) || /pipeline (?:par|total|ouvert|en cours|de |des )/.test(n) ? "sum"
        : /(nombre|combien|volume|compte)/.test(n) ? "count" : null;
      if (!meas) return null;
      GROUPS.forEach(function (g) { if (!by && g[1].test(n)) by = g[0]; });
      if ((by === "source" || by === "segment") && !dimOfKey(by)) by = null;
      if (!by) (M.dims || []).forEach(function (dm) { if (!by && n.indexOf("par " + norm(dm.label)) >= 0) by = dm.key; });
      var intent = /(calcul|indicateur|kpi|combien|quel|montre|affiche|donne|veux|voir|suivre|mesure|ajoute|cree)/.test(n) || /^(?:le |la |les |mon |ma |notre |nos )?(montant|nombre|total|somme|panier|ticket|taux|part|proportion|pourcentage|duree|temps|cycle|delai|volume)/.test(n);
      if (!intent && !by) return null;
      var pop = /(gagn|remport|\bsignes?\b)/.test(n) ? "won" : /perdu/.test(n) ? "lost" : /(ouvert|en cours)/.test(n) ? "open" : /(\bclos\b|ferme)/.test(n) ? "closed" : null, v = money(o);
      if (v && /(plus de|au dessus|superieur|au moins|a partir de)/.test(n)) f.min = v; else if (v && /(moins de|inferieur|en dessous|au dessous)/.test(n)) f.max = v;
      (M.dims || []).forEach(function (dm) { if (dm.key === by) return; dm.values.forEach(function (val) { if (!f.dim && norm(val.v).length > 2 && hasW(n, norm(val.v))) f.dim = { key: dm.key, value: val.v }; }); });
      if (stageHit >= 0 && meas !== "stagetime" && by !== "stage" && N2 && /( en | a l etape | au stade | dans l etape )/.test(" " + n + " ")) f.stage = norm(M.stages[stageHit]);
      Object.keys(names).forEach(function (h) { var full = norm(names[h]); if (full && has(n, full)) f.owner = h; });
      if (by !== "reason" && (pop === "lost" || meas === "share")) M.reasons.forEach(function (r) { if (r.name !== "(vide)" && !f.reason && hasW(n, norm(r.name))) f.reason = r.name; });
      if ((m = n.match(/(\d+) derni\w+ mois/) || n.match(/depuis (\d+) mois/))) f.since = +m[1];
      if (f.reason && !pop) pop = "lost";
      if (meas === "winrate") pop = "closed"; else if (meas === "cycle") pop = "won"; else if (meas === "stagetime") pop = "all";
      else if (!pop) pop = meas === "avg" || meas === "median" ? (/(panier|ticket)/.test(n) ? "won" : "all") : meas === "sum" && /pipeline/.test(n) ? "open" : "all";
      if (meas === "share" && !Object.keys(f).length && pop === "all") return null;
      var stat = /moyen/.test(n) ? "avg" : "median", P = { won: " gagnés", lost: " perdus", open: " ouverts", closed: " clos", all: /(^| )cree/.test(n) ? " créés" : "" };
      var LBL = { count: "Nombre de deals", sum: "Montant total des deals", avg: "Montant moyen des deals", median: "Montant médian des deals", share: "Part des deals", winrate: "Taux de signature", cycle: (stat === "avg" ? "Durée moyenne" : "Durée médiane") + " d’une vente", stagetime: "Temps passé en " + (stageHit >= 0 ? qt(M.stages[stageHit]) : "") };
      var plain = meas === "winrate" || meas === "cycle" || meas === "stagetime", lab = LBL[meas] + (plain ? "" : P[pop]);
      var ft = (f.dim ? " " + qt(f.dim.value) : "") + (f.stage ? " en " + qt(M.stages[stageHit]) : "") + (f.min ? " de plus de " + fmt.eur(f.min) : "") + (f.max ? " de moins de " + fmt.eur(f.max) : "") + (f.owner ? " de {who:" + f.owner + "}" : "") + (f.reason ? " pour " + qt(f.reason) : "") + (f.since ? " créés depuis " + f.since + " mois" : "");
      lab += ft && plain ? ", deals" + ft : ft;
      if (by) lab += ", " + (BYTXT[by] || "par " + (dimOfKey(by) ? dimOfKey(by).label.toLowerCase() : by));
      return { id: "k:" + n.slice(0, 80), measure: meas, pop: pop, filters: f, by: by, stat: stat, stage: meas === "stagetime" ? norm(M.stages[stageHit]) : null, text: o, label: lab };
    };
    String(text || "").split(/[\n;!?]+|\.(?=\s|$)/).map(function (x) { return x.trim(); }).filter(Boolean).forEach(function (o) {
      var n = norm(o).replace(new RegExp("\\b(" + NUMS + ")(?= (?:" + UNITS + "|fois|deals? sur)\\b)", "g"), function (w) { return NUMW[w]; }).replace(new RegExp("\\bsur (" + NUMS + ")\\b", "g"), function (w, a) { return "sur " + NUMW[a]; });
      var hit = [], masks = [], m, a, b, d, v, ans;
      var push = function (label, set, answers) { var an = {}; for (var k in answers || {}) if (answers[k] != null) an[k] = answers[k]; hit.push({ label: label, set: set, answers: an }); };
      var exclT = /(ignor|exclu|ne compt\w* pas|ne pas compter|sans compter|\bhors |retir|enlev|de cote|ne juge\w* pas|ne regard\w* pas|pas de la vente|oublie|tenir compte|tenez pas compte)/.test(n), backT = /(reintegr|remet|recompt|a nouveau|rejuge)/.test(n);
      var staleK = /(sans mouvement|sans nouvelle|sans activite|sans reponse|sans signe|ne bouge|a l arret|\bmorts?\b|stagn|inactif|bloque|meme etape|sans changer d etape|dort|dorment|enlis|perime)/.test(n), many = /(surtout|principalement|essentiellement|majorit|uniquement|que de|que du|100|vien|fait|faisons|sommes)/.test(n);
      var dur = n.match(DUR), stageHit = -1, exc = o.search(/\b(sauf|except[ée]|hormis|mais pas|à l[’']exception)\b/i);
      M.stages.forEach(function (st, i) { var w = norm(st); if (w.length >= 3 && has(n, w) && (stageHit < 0 || w.length > norm(M.stages[stageHit]).length)) stageHit = i; });

      // durations: one stage, every stage, the length of a sale, or the period to judge
      if (dur && stageHit >= 0 && exc < 0 && N2 && !/(qualifi|serieux)/.test(n) && (staleK || /(rest|dur|normal|peut|jusqu|attend|prend|train|long)/.test(n))) { d = days(dur); a = { stageDays: {} }; a.stageDays[norm(M.stages[stageHit])] = d; push("En " + qt(M.stages[stageHit]) + ", un deal n’est à l’arrêt qu’après " + d + " jours", a); }
      else if (dur && staleK && !/cycle/.test(n)) { d = days(dur); push("Un deal est à l’arrêt après " + d + " jours " + (N2 ? "dans la même étape" : "sans signature"), { stagDays: d }, { stale: optOf("stale", { stagDays: d }) }); }
      else if (staleK && (m = n.match(/(\d+(?: \d)?)\s*(?:x|fois)/))) { v = parseFloat(m[1].replace(" ", ".")); if (v >= 1 && v <= 6) push("Un deal est à l’arrêt au-delà de " + String(v).replace(".", ",") + " fois la durée normale", { stagMult: v, stagDays: null }, { stale: true }); }
      else if (dur && /(cycle|vente\w* (?:dure|prend|se signe|se fait|se conclu)\w*|signe\w* en|signature en|pour signer|delai de vente|duree d une vente)/.test(n)) { d = days(dur); push("Chez vous, une vente normale dure jusqu’à " + d + " jours", { cycle: d }, { cycle: optOf("cycle", { cycle: d }) }); }
      else if (!staleK && /(juge|regard|analys|gard|seulement|uniquement|que les|compt|histori|periode|recent)/.test(n)) {
        m = n.match(/(\d+) derni\w+ (mois|ans?|annees?)/) || n.match(/depuis (\d+) (mois|ans?|annees?)/) || (/(derniere annee|annee ecoulee)/.test(n) ? ["", "12", "mois"] : null);
        if (m) { v = months(m); push("Je ne juge que les deals créés depuis " + v + " mois ; les deals encore ouverts restent tous", { since: v }, { since: optOf("since", { since: v }) }); }
        else if (/(tout l historique|toute la periode|tout le fichier|toutes les annees)/.test(n)) push("Je juge tout l’historique de votre fichier", { since: null }, { since: optOf("since", { since: null }) });
      }

      // calculation methods: what the signature rate is computed on, where the length of a sale starts
      if (/(taux de (?:signature|closing|conversion|transformation|reussite)|win rate)/.test(n) && /(calcul|compte|mesur|base)/.test(n) && !/\d/.test(n)) {
        if (stageHit >= 0 && N2) push("Le taux de signature se calcule sur les deals arrivés en " + qt(M.stages[stageHit]), { qualStage: stageHit }, { qual: optOf("qual", { qualStage: stageHit }) });
        else if (/(tous les deals|deals crees|des la creation|toutes les opportunites|tout le pipeline)/.test(n)) push("Le taux de signature se calcule sur tous les deals créés", { qualStage: 0 }, { qual: optOf("qual", { qualStage: 0 }) });
      }
      if (!dur && stageHit >= 0 && N2 && /(cycle|duree d une vente|duree de vente|duree des ventes|delai de vente)/.test(n) && /(a partir|depuis|des l|commence|demarre|se compte|se calcule|se mesure)/.test(n)) push("La durée d’une vente se compte à partir de l’étape " + qt(M.stages[stageHit]), { cycleFrom: norm(M.stages[stageHit]) });

      // what a normal signature rate is here
      if (/\d\s*(%|pour ?cent)/i.test(o) && !money(o) && (m = n.match(/(?:win rate|taux de (?:closing|conversion|transformation|signature|reussite))[a-z ]*?(\d{1,2})(?:\s*(?:a|et)\s*(\d{1,2}))?/))) { a = +m[1]; b = m[2] ? +m[2] : a + 5; if (!m[2]) a = Math.max(1, a - 5); push("Un taux de signature normal chez vous : " + a + " à " + b + NB + "%", { wrMin: a, wrMax: b }, { motion: optOf("motion", { wrMin: a, wrMax: b }) }); }
      else if ((m = n.match(/(\d+) deals? sur (\d+)/)) && +m[2] > 0 && +m[1] <= +m[2] && /(sign|gagn|transform|conclu|clos)/.test(n)) { v = Math.round(+m[1] / +m[2] * 100); a = Math.max(1, v - 5); b = v + 5; push("Un taux de signature normal chez vous : " + a + " à " + b + NB + "%", { wrMin: a, wrMax: b }, { motion: true }); }
      else if (!exclT && many && /(inbound|entrant)/.test(n)) push("Vos deals viennent surtout de demandes entrantes : 30 à 45" + NB + "% de signature attendus", { wrMin: 30, wrMax: 45 }, { motion: optOf("motion", { wrMin: 30, wrMax: 45 }) });
      else if (!exclT && many && /(outbound|prospection|a froid|cold)/.test(n)) push("Vos deals viennent surtout de la prospection : 10 à 20" + NB + "% de signature attendus", { wrMin: 10, wrMax: 20 }, { motion: optOf("motion", { wrMin: 10, wrMax: 20 }) });

      // amounts: a floor under which deals are not judged, a catalogue price, or a placeholder
      if ((v = money(o))) {
        var isMode = function (set) { return optOf("fixed", set) === true ? null : optOf("fixed", set); }, eurTxt = fmt.int(v) + NB + "€";
        if ((/(moins de|inferieur|en dessous|au dessous|sous les|plus petit)/.test(n) && (exclT || /ne compt/.test(n))) || (/(plus de|au dessus|superieur|a partir de|au moins)/.test(n) && /(seulement|uniquement|que les|\bque\b)/.test(n))) push("Je ne juge que les deals d’au moins " + eurTxt, { minAmount: v });
        else if (/(par defaut|en attendant|pas un (?:vrai )?(?:prix|tarif)|n est pas (?:un|notre)|au hasard|invente|bidon|provisoire)/.test(n)) push(eurTxt + " n’est pas un tarif : c’est un montant mis en attendant", { removeFixed: v }, { fixed: isMode({ removeFixed: v }) });
        else if (/(prix fixe|forfait|offre|tarif|abonnement|licence|pack|catalogue|prix)/.test(n)) push(eurTxt + " est un prix de votre catalogue", { addFixed: v }, { fixed: isMode({ addFixed: v }) });
      }

      // signature dates at month end, the stage where a deal becomes serious
      if (/(fin de mois|dernier jour du mois|debut de mois|1er du mois|premier du mois)/.test(n)) {
        if (/(par defaut|au hasard|pour remplir|sans raison|bidon|arbitraire)/.test(n)) push("Vos dates de fin de mois sont mises par défaut", { eomOk: false }, { eom: optOf("eom", { eomOk: false }) });
        else if (/(factur|demarr|contrat|normal|voulu|regle|toujours)/.test(n)) push("Dater à fin de mois est votre règle", { eomOk: true }, { eom: optOf("eom", { eomOk: true }) });
      }
      if (/(qualifi|serieux|vrai deal|compte vraiment)/.test(n) && stageHit >= 0) push("Un deal est sérieux à partir de " + qt(M.stages[stageHit]), { qualStage: stageHit }, { qual: optOf("qual", { qualStage: stageHit }) });

      // what a loss reason means in this company
      if (/(veut dire|signifie|c est quand|correspond|on coche|est coche|utilis|sert a|c est a dire|est une case|est la case|\bveut\b)/.test(n)) M.reasons.forEach(function (r) {
        var rn = norm(r.name); if (r.name === "(vide)" || n.indexOf(rn) < 0) return; var rest = n.replace(rn, " ");
        var cls = /(ne repond|plus de nouvelle|plus de reponse|silence|fantome|ghost|sans decision|pas de decision|ne donne plus|abandonne|disparai|injoignable|ne rappelle)/.test(rest) ? "nd" : /concurren/.test(rest) ? "comp" : /(trop cher|prix|tarif)/.test(rest) ? "price" : /(fourre tout|par defaut|ne sait pas|ne veut rien dire|rien de precis)/.test(rest) ? "vague" : null;
        if (!cls) return; var set = { reasons: {} }, an = {}; set.reasons[r.name] = cls; an["reason:" + r.name] = optOf("reason:" + r.name, set); push(qt(r.name) + " veut dire : " + CLS[cls], set, an);
      });

      // deals to set aside (any category of the file), or the pipeline to judge
      if (exclT || backT) (M.dims || []).forEach(function (dm) { dm.values.forEach(function (val) {
        if (!has(n, norm(val.v))) return; var on = M.rules.exclude.some(function (x) { return x.key === dm.key && norm(x.value) === norm(val.v); }), an = {}; an["dim:" + dm.key] = true;
        if (backT && !exclT) { if (on) push("Je juge de nouveau les deals " + qt(val.v), { toggleExclude: M.rules.exclude.filter(function (x) { return x.key === dm.key && norm(x.value) === norm(val.v); })[0] }, an); }
        else push("Je mets de côté les deals " + qt(val.v) + " (" + dm.label + ")", { addExclude: { key: dm.key, value: val.v } }, an);
      }); });
      else if (M.rules.pipelines.length > 1 && /(pipeline|juge|regard|analys|seulement|uniquement|garde)/.test(n)) {
        if (/pipeline/.test(n) && /(tous|ensemble)/.test(n)) push("Je juge tous vos pipelines ensemble", { pipeline: "*" }, { pipeline: optOf("pipeline", { pipeline: "*" }) });
        else M.rules.pipelines.forEach(function (pp) { if (has(n, norm(pp.name))) push("Je juge le pipeline " + qt(pp.name), { pipeline: pp.name }, { pipeline: optOf("pipeline", { pipeline: pp.name }) }); });
      }

      // people who no longer sell here
      var hashes = Object.keys(names), first = function (h) { return norm(names[h]).split(" ")[0]; };
      hashes.forEach(function (h) {
        var full = norm(names[h]); if (!full) return; var f1 = first(h), uniq = hashes.filter(function (x) { return first(x) === f1; }).length === 1;
        if (!(has(n, full) || (uniq && f1.length >= 3 && (" " + n + " ").indexOf(" " + f1 + " ") >= 0))) return;
        var onV = /(vend toujours|vend encore|est revenu|toujours (?:la|chez)|de retour|reintegr)/.test(n), offV = /(ne vend\w* plus|a quitte|est partie?\b|n est plus|plus chez (?:nous|vous)|plus dans l equipe|demission|licenci|manag|direct(?:eur|rice)|compte (?:de )?test|ne fait plus|retraite|conge|arret maladie|change de poste)/.test(n);
        if (onV) push("{who:" + h + "} vend toujours chez vous", { ownerOn: h }, { team: true });
        else if (offV) push("{who:" + h + "} ne vend plus chez vous : je sors cette personne des comparaisons, et je vous montre les deals qu’elle porte encore", { ownerOff: h }, { team: true });
        if (onV || offV) { masks.push([names[h], h]); masks.push([names[h].split(/\s+/)[0], h]); }
      });

      if (!hit.length) { var kp = readKpi(o, n, stageHit); if (kp) push("Nouvel indicateur : " + kp.label, { addKpi: kp }); }
      if (!hit.length) return out.notes.push(o);
      if (exc >= 0 && dur) out.notes.push(o.slice(exc));   // the exception needs its own sentence, with its own delay
      // names never leave the screen: in what is kept of the sentence, a person is replaced by a reference
      var mask = o; masks.forEach(function (p) { if (p[0]) mask = mask.replace(new RegExp(rxEsc(p[0]), "gi"), "{who:" + p[1] + "}"); });
      if (masks.length && mask === o) mask = null;
      hit.forEach(function (h) { h.source = o; h.mask = mask; out.understood.push(h); });
    });
    return out;
  }

  // what a change of rules moves, in words: shown to the user before a rule is applied
  var BLK = { stalled: "les deals à l’arrêt", orphans: "les deals sans porteur", amounts: "les montants", dates: "les dates de signature", journey: "les pertes en fin de parcours", rep: "l’écart entre commerciaux", reasons: "les raisons de perte" };
  function effect(a, b) {
    var out = [], idx = function (M) { var o = {}; M.story.blocks.forEach(function (x) { o[x.key] = x; }); return o; }, A = idx(a), B = idx(b), bad = function (z) { return !!z && z.tone === "r"; };
    var st = function (M, id) { var c = M.checks.filter(function (x) { return x.id === id; })[0]; return c && c.status !== "na" ? c.status : null; };
    if (a.meta.rows !== b.meta.rows) out.push(fmt.int(b.meta.rows) + " deals jugés au lieu de " + fmt.int(a.meta.rows));
    var parts = [];
    if (fmt.eur(a.story.alive) !== fmt.eur(b.story.alive)) parts.push("pipeline vivant : " + fmt.eur(b.story.alive) + " au lieu de " + fmt.eur(a.story.alive));
    if (a.pipe.unionN !== b.pipe.unionN) parts.push(b.pipe.unionN + " deals à l’arrêt au lieu de " + a.pipe.unionN);
    if (parts.length) out.push(parts.join(", "));
    if (a.kpi.k2 != null && b.kpi.k2 != null && fmt.pct(a.kpi.k2) !== fmt.pct(b.kpi.k2)) out.push("taux de signature : " + fmt.pct(b.kpi.k2) + " au lieu de " + fmt.pct(a.kpi.k2));
    Object.keys(BLK).forEach(function (k) {
      var x = A[k], y = B[k];
      if (bad(y) && !bad(x)) out.push("nouveau constat sur " + BLK[k]);
      else if (bad(x) && !bad(y)) out.push("constat levé sur " + BLK[k]);
      else if (x && y && y.tone === "g" && x.tone !== "g") out.push("point levé sur " + BLK[k]);
      else if (x && y && (x.tone !== y.tone || x.read !== y.read)) out.push("autre lecture pour " + BLK[k]);
    });
    (b.custom || []).forEach(function (k) { if (!(a.custom || []).some(function (x) { return x.id === k.id; })) out.push(k.label + " : " + k.f); });
    if (st(b, "C1") && st(a, "C1") !== st(b, "C1")) out.push("votre durée de vente est maintenant jugée " + { g: "normale", o: "un peu longue", r: "trop longue" }[st(b, "C1")]);
    if (st(b, "B2") && st(a, "B2") !== st(b, "B2")) out.push("votre taux de signature est maintenant jugé " + { g: "dans la norme", o: "sous la norme", r: "très en dessous de la norme" }[st(b, "B2")]);
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

  var api = { diff: diff, applyRule: applyRule, inverse: inverse, effect: effect, interpret: interpret, parseCSV: parseCSV, proposeMapping: proposeMapping, fieldLabel: fieldLabel, isPiiField: isPiiField, FIELDS: FIELDS, REQUIRED: REQUIRED, anonymize: anonymize, analyze: analyze, fmt: fmt };
  if (typeof module !== "undefined" && module.exports) module.exports = api; else root.BIF = api;
})(typeof window !== "undefined" ? window : globalThis);

// Public configuration of the app. Both values are publishable (they ship to every browser):
// row-level security in supabase/schema.sql only lets anonymous visitors INSERT a lead, never read.
// Leave empty to run without a backend: the lead buttons then say they are not active yet.
window.FSFA_CONFIG = {
  supabaseUrl: "",
  supabaseAnonKey: ""
};

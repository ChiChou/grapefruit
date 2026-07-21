module.exports = function binding(options) {
  const name = typeof options === "string" ? options : options.bindings;
  const key = name.startsWith("better_sqlite3")
    ? "IGF_SQLITE_BINDING"
    : "IGF_FRIDA_BINDING";
  const file = process.env[key];
  if (!file) throw new Error(`Missing native binding for ${name}`);

  const mod = { exports: {} };
  process.dlopen(mod, file);
  return mod.exports;
};

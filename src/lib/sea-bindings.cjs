module.exports = function binding(options) {
  const name = typeof options === "string" ? options : options.bindings;
  const file = process.env.IGF_FRIDA_BINDING;
  if (!file) throw new Error(`Missing native binding for ${name}`);

  const mod = { exports: {} };
  process.dlopen(mod, file);
  return mod.exports;
};

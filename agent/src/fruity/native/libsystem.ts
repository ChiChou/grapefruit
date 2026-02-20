let cached: {
  free: NativeFunction<void, [NativePointerValue]>;
  fcntl: NativeFunction<number, [number, number, NativePointerValue]>;
  strcmp: NativeFunction<number, [NativePointerValue, NativePointerValue]>;
  fnmatch: NativeFunction<
    number,
    [NativePointerValue, NativePointerValue, number]
  >;
};

export default function api() {
  if (cached) return cached;

  const libsystem = Process.getModuleByName("libSystem.B.dylib");
  const e = (name: string) => libsystem.getExportByName(name);

  cached = {
    free: new NativeFunction(e("free"), "void", ["pointer"]),
    fcntl: new NativeFunction(e("fcntl"), "int", ["int", "int", "pointer"]),
    strcmp: new NativeFunction(e("strcmp"), "int", ["pointer", "pointer"]),
    fnmatch: new NativeFunction(e("fnmatch"), "int", [
      "pointer",
      "pointer",
      "int",
    ]),
  };

  return cached;
}

let cached: {
  CFDataGetLength: NativeFunction<number, [NativePointerValue]>;
  CFDataGetBytePtr: NativeFunction<NativePointer, [NativePointerValue]>;
};

export default function api() {
  if (cached) return cached;

  const CoreFoundation = Process.getModuleByName("CoreFoundation");
  const CFDataGetLength = new NativeFunction(
    CoreFoundation.getExportByName("CFDataGetLength"),
    "long",
    ["pointer"],
  );

  const CFDataGetBytePtr = new NativeFunction(
    CoreFoundation.getExportByName("CFDataGetBytePtr"),
    "pointer",
    ["pointer"],
  );

  cached = {
    CFDataGetLength,
    CFDataGetBytePtr,
  };

  return cached;
}

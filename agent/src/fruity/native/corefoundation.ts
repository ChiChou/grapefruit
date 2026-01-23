let cached: {
  CFDataGetLength: NativeFunction<number, [NativePointerValue]>;
  CFDataGetBytePtr: NativeFunction<NativePointer, [NativePointerValue]>;
  CFRetain: NativeFunction<NativePointer, [NativePointerValue]>;
  CFRelease: NativeFunction<void, [NativePointerValue]>;
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

  const CFRelease = new NativeFunction(
    CoreFoundation.findExportByName("CFRelease")!,
    "void",
    ["pointer"],
  );

  const CFRetain = new NativeFunction(
    CoreFoundation.findExportByName("CFRetain")!,
    "pointer",
    ["pointer"],
  );

  cached = {
    CFDataGetLength,
    CFDataGetBytePtr,
    CFRetain,
    CFRelease,
  };

  return cached;
}

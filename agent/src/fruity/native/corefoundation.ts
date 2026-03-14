let cached: {
  CFDataGetLength: NativeFunction<number, [NativePointerValue]>;
  CFDataGetBytePtr: NativeFunction<NativePointer, [NativePointerValue]>;
  CFRetain: NativeFunction<NativePointer, [NativePointerValue]>;
  CFRelease: NativeFunction<void, [NativePointerValue]>;
};

export default function api() {
  if (cached) return cached;

  const e = (name: string) => CoreFoundation.getExportByName(name);

  const CoreFoundation = Process.getModuleByName("CoreFoundation");
  const CFDataGetLength = new NativeFunction(e("CFDataGetLength"), "long", [
    "pointer",
  ]);

  const CFDataGetBytePtr = new NativeFunction(
    e("CFDataGetBytePtr"),
    "pointer",
    ["pointer"],
  );

  const CFRelease = new NativeFunction(e("CFRelease"), "void", ["pointer"]);
  const CFRetain = new NativeFunction(e("CFRetain"), "pointer", ["pointer"]);

  cached = {
    CFDataGetLength,
    CFDataGetBytePtr,
    CFRetain,
    CFRelease,
  };

  return cached;
}

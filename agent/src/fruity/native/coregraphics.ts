let cached: {
  CGImageGetWidth: NativeFunction<number, [NativePointerValue]>;
  CGImageGetHeight: NativeFunction<number, [NativePointerValue]>;
};

export default function api() {
  if (cached) return cached;

  const CoreGraphics = Process.getModuleByName("CoreGraphics");
  const e = (name: string) => CoreGraphics.getExportByName(name);

  const CGImageGetWidth = new NativeFunction(e("CGImageGetWidth"), "uint", [
    "pointer",
  ]);

  const CGImageGetHeight = new NativeFunction(e("CGImageGetHeight"), "uint", [
    "pointer",
  ]);

  cached = {
    CGImageGetWidth,
    CGImageGetHeight,
  };

  return cached;
}

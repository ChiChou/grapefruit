let cached: {
  CGImageGetWidth: NativeFunction<number, [NativePointerValue]>;
  CGImageGetHeight: NativeFunction<number, [NativePointerValue]>;
};

export default function api() {
  if (cached) return cached;

  const CoreGraphics = Process.getModuleByName("CoreGraphics");

  const CGImageGetWidth = new NativeFunction(
    CoreGraphics.getExportByName("CGImageGetWidth"),
    "uint",
    ["pointer"],
  );

  const CGImageGetHeight = new NativeFunction(
    CoreGraphics.getExportByName("CGImageGetHeight"),
    "uint",
    ["pointer"],
  );

  cached = {
    CGImageGetWidth,
    CGImageGetHeight,
  };

  return cached;
}

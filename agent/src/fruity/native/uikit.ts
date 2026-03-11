let cached: {
  UIImagePNGRepresentation: NativeFunction<NativePointer, [NativePointerValue]>;
};

export default function api() {
  if (cached) return cached;

  const UIKit = Process.getModuleByName("UIKit");
  const UIImagePNGRepresentation = new NativeFunction(
    UIKit.getExportByName("UIImagePNGRepresentation"),
    "pointer",
    ["pointer"],
  );

  cached = {
    UIImagePNGRepresentation,
  };

  return cached;
}

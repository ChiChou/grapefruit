export default function api() {
  const foundation = Process.getModuleByName("Foundation");
  const NSHomeDirectory = new NativeFunction(
    foundation.getExportByName("NSHomeDirectory"),
    "pointer",
    [],
  );

  const NSTemporaryDirectory = new NativeFunction(
    foundation.getExportByName("NSTemporaryDirectory"),
    "pointer",
    [],
  );

  return {
    NSHomeDirectory,
    NSTemporaryDirectory,
  };
}

interface Module16 {
  findExportByName(
    moduleName: string | null,
    exportName: string,
  ): NativePointer | null;
  getExportByName(moduleName: string | null, exportName: string): NativePointer;
}

export function findGlobalExport(name: string) {
  if ("findExportByName" in Module)
    return (Module as unknown as Module16).findExportByName(null, name);

  return Module.findGlobalExportByName(name);
}

export function getGlobalExport(name: string) {
  if ("getExportByName" in Module)
    return (Module as unknown as Module16).getExportByName(null, name);

  return Module.getGlobalExportByName(name);
}

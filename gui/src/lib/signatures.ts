export const types = [
  "pointer", "int", "uint", "long", "ulong", "size_t", "ssize_t",
  "int8", "uint8", "int16", "uint16", "int32", "uint32", "int64", "uint64",
  "float", "double", "bool", "char *", "id", "void",
] as const;

export type FridaType = string | FridaType[];

export interface NativeType {
  c: string;
  canonical: string;
  frida: FridaType;
  display: string;
  approximate: boolean;
}

export interface Template {
  args: (NativeType & { name: string })[];
  returns: NativeType;
  source: string;
  header: string;
  module: string;
  arch: string;
  variadic: boolean;
  nameOnly: boolean;
}

export function display(type: NativeType): string {
  if (type.frida === "pointer" && type.display === "utf8") return "char *";
  if (type.frida === "pointer" && type.display === "objc") return "id";
  return typeof type.frida === "string" && (types as readonly string[]).includes(type.frida) ? type.frida : "pointer";
}

export async function lookup(platform: string, name: string, module: string | null, arch: string | undefined, signal: AbortSignal): Promise<Template | null> {
  const params = new URLSearchParams({ platform, name });
  if (module) params.set("module", module);
  if (arch) params.set("arch", arch);
  const response = await fetch(`/api/signatures?${params}`, { signal });
  if (!response.ok) throw new Error("Offline templates are unavailable. Enter types manually.");
  const data = await response.json() as { match: Template | null };
  return data.match;
}

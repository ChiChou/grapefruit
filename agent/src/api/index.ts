export type Schema = [NativeType, NativeType[]]
export function api<T>(library: string, schema: Record<keyof T, Schema>): Record<keyof T, NativeFunction> {
  const result: Record<keyof T, NativeFunction> = {} as Record<keyof T, NativeFunction>
  for (const [name, args] of Object.entries(schema)) {
    const [retType, argTypes] = args as Schema
    const p = Module.findExportByName(library, name)
    if (!p) throw new Error(`unable to resolve symbol: ${library}!${name}`)
    result[name as keyof T] = new NativeFunction(p, retType, argTypes)
  }
  return result
}

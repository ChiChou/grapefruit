function safeBound(p: NativePointer): NativePointer {
  const range = Process.findRangeByAddress(p);
  if (range && range.protection.includes("r"))
    return range.base.add(range.size);

  const mod = Process.findModuleByAddress(p);
  if (mod) return mod.base.add(mod.size);

  throw new Error(`memory address ${p} cannot be read`);
}

export function dump(address: string, size: number) {
  const LIMIT = 2048;
  const p = ptr(address);
  const maxSize = Math.min(size, safeBound(p).sub(p).toUInt32(), LIMIT);
  return p.readByteArray(maxSize);
}

export interface Range {
  base: string;
  size: number;
  protection: string;
}

export function allocedRanges(): Range[] {
  return Process.enumerateMallocRanges().map(({ base, size, protection }) => ({
    base: base.toString(),
    size,
    protection,
  }));
}

// todo: search

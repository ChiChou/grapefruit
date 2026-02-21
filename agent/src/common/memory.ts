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

export function addressInfo(address: string) {
  const p = ptr(address);

  const range = Process.findRangeByAddress(p);
  const mod = Process.findModuleByAddress(p);

  return {
    module: mod
      ? { name: mod.name, base: mod.base.toString(), size: mod.size, path: mod.path }
      : null,
    range: range
      ? { base: range.base.toString(), size: range.size, protection: range.protection, file: range.file ?? null }
      : null,
  };
}

let scanning = false;

export function scan(pattern: string, protection: string = "r--") {
  if (scanning) throw new Error("scan already in progress");
  scanning = true;

  const ranges = Process.enumerateRanges(protection);
  let matchCount = 0;

  (async () => {
    for (let i = 0; i < ranges.length; i++) {
      if (!scanning) break;
      const range = ranges[i];

      send({ subject: "memoryScan", event: "progress", current: i, total: ranges.length });

      await Memory.scan(range.base, range.size, pattern, {
        onMatch(address, size) {
          if (!scanning) return "stop";
          matchCount++;
          const preview = address.readByteArray(Math.min(size, 64));
          send({
            subject: "memoryScan",
            event: "match",
            address: address.toString(),
            size,
          }, preview);
        },
        onError() {
          // skip unreadable ranges
        },
        onComplete() {},
      });
    }
    scanning = false;
    send({ subject: "memoryScan", event: "done", count: matchCount });
  })();
}

export function stopScan() {
  scanning = false;
}

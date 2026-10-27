/** Minimal executable images with one code section, generated without a host compiler. */
export function elf(machine: number, code: Uint8Array, wide: boolean, thumb = false): ArrayBuffer {
  const bytes = new Uint8Array(0x2100);
  const view = new DataView(bytes.buffer);
  const u16 = (at: number, value: number) => view.setUint16(at, value, true);
  const u32 = (at: number, value: number) => view.setUint32(at, value, true);
  const word = (at: number, value: number) => wide ? view.setBigUint64(at, BigInt(value), true) : u32(at, value);
  bytes.set([0x7f, 69, 76, 70, wide ? 2 : 1, 1, 1]);
  u16(16, 2); u16(18, machine); u32(20, 1);
  word(24, 0x1000 + (thumb ? 1 : 0));
  word(wide ? 32 : 28, wide ? 64 : 52);
  word(wide ? 40 : 32, 0x2000);
  u32(wide ? 48 : 36, machine === 40 ? 0x05000000 : 0);
  u16(wide ? 52 : 40, wide ? 64 : 52);
  u16(wide ? 54 : 42, wide ? 56 : 32);
  u16(wide ? 56 : 44, 1);
  u16(wide ? 58 : 46, wide ? 64 : 40);
  u16(wide ? 60 : 48, 3);
  u16(wide ? 62 : 50, 2);
  const ph = wide ? 64 : 52;
  u32(ph, 1);
  if (wide) {
    u32(ph + 4, 5); word(ph + 8, 0x1000); word(ph + 16, 0x1000); word(ph + 24, 0x1000);
    word(ph + 32, code.length); word(ph + 40, code.length); word(ph + 48, 0x1000);
  } else {
    u32(ph + 4, 0x1000); u32(ph + 8, 0x1000); u32(ph + 12, 0x1000);
    u32(ph + 16, code.length); u32(ph + 20, code.length); u32(ph + 24, 5); u32(ph + 28, 0x1000);
  }
  const sh = 0x2000 + (wide ? 64 : 40);
  u32(sh, 1); u32(sh + 4, 1); word(sh + 8, 6);
  word(sh + (wide ? 16 : 12), 0x1000); word(sh + (wide ? 24 : 16), 0x1000);
  word(sh + (wide ? 32 : 20), code.length); word(sh + (wide ? 48 : 32), 4);
  const strings = sh + (wide ? 64 : 40);
  u32(strings, 7); u32(strings + 4, 3);
  word(strings + (wide ? 24 : 16), 0x20e0); word(strings + (wide ? 32 : 20), 17);
  word(strings + (wide ? 48 : 32), 1);
  bytes.set(new TextEncoder().encode("\0.text\0.shstrtab\0"), 0x20e0);
  bytes.set(code, 0x1000);
  return bytes.buffer;
}

export function macho(code: Uint8Array): ArrayBuffer {
  const bytes = new Uint8Array(0x1000 + code.length);
  const view = new DataView(bytes.buffer);
  const u32 = (at: number, value: number) => view.setUint32(at, value, true);
  const u64 = (at: number, value: number) => view.setBigUint64(at, BigInt(value), true);
  const text = (at: number, value: string) => bytes.set(new TextEncoder().encode(value), at);
  u32(0, 0xfeedfacf); u32(4, 0x100000c); u32(8, 2); u32(12, 2);
  u32(16, 2); u32(20, 176);
  u32(32, 0x19); u32(36, 152); text(40, "__TEXT");
  u64(56, 0x1000); u64(64, 0x2000); u64(72, 0); u64(80, bytes.length);
  u32(88, 5); u32(92, 5); u32(96, 1);
  text(104, "__text"); text(120, "__TEXT");
  u64(136, 0x2000); u64(144, code.length); u32(152, 0x1000); u32(156, 2); u32(168, 0x80000400);
  u32(184, 0x80000028); u32(188, 24); u64(192, 0x1000);
  bytes.set(code, 0x1000);
  return bytes.buffer;
}

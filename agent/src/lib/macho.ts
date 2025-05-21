const MH_EXECUTE = 0x2;
const MH_DYLIB = 0x6;
const MH_DYLINKER = 0x7;
const MH_BUNDLE = 0x8;

const MH_PIE = 0x200000;
const MH_NO_HEAP_EXECUTION = 0x1000000;

const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_ENCRYPTION_INFO = 0x21;

const HEADER_SIZE_64 = 8 * 4;

function flags(mod: Module) {
  return mod.base.add(0x18).readU32();
}

export function pie(mod: Module) {
  return Boolean(flags(mod) & MH_PIE);
}

export function nx(mod: Module) {
  return Boolean(flags(mod) & MH_NO_HEAP_EXECUTION);
}

interface EncryptInfo {
  ptr: NativePointer;
  offset: number;
  size: number;
  offsetOfCmd: number;
  sizeOfCmd: number;
  cryptid: number;
}

export function encryptionInfo(mod: Module): EncryptInfo | null {
  const header = mod.base;
  const magic = header.readU32();
  if (magic !== 0xfeedface && magic !== 0xfeedfacf) {
    throw new Error("Invalid Mach-O header magic value");
  }

  const fileType = header.add(0xc).readU32();
  const ncmds = header.add(0x10).readU32();
  const sizeOfCmds = header.add(0x14).readU32();

  for (let p = header.add(HEADER_SIZE_64), i = 0; i < ncmds; i++) {
    const cmd = p.readU32();
    const cmdSize = p.add(0x4).readU32();

    if (cmd === LC_ENCRYPTION_INFO_64 || cmd === LC_ENCRYPTION_INFO) {
      const cryptoff = p.add(8).readU32();
      const cryptsize = p.add(12).readU32();
      const cryptid = p.add(16).readU32();
      return {
        ptr: p,
        offset: cryptoff,
        size: cryptsize,
        offsetOfCmd: p.sub(header).toInt32(),
        sizeOfCmd: cmdSize,
        cryptid,
      };
    }

    p = p.add(cmdSize);
  }

  return null;
}

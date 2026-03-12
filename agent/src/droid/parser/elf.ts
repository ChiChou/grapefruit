const ELFMAG = 0x464c457f; // "\x7fELF" as little-endian uint32
const ELFCLASS64 = 2;
const ELFDATA2MSB = 2;

// p_type
const PT_DYNAMIC = 2;

const cm = new CModule(`
  #include <stdint.h>
  #include <stddef.h>

  /* ELF64 header */
  typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
  } Elf64_Ehdr;

  /* ELF32 header */
  typedef struct {
    uint8_t  e_ident[16];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint32_t e_entry;
    uint32_t e_phoff;
    uint32_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
  } Elf32_Ehdr;

  /* ELF64 program header */
  typedef struct {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
  } Elf64_Phdr;

  /* ELF32 program header */
  typedef struct {
    uint32_t p_type;
    uint32_t p_offset;
    uint32_t p_vaddr;
    uint32_t p_paddr;
    uint32_t p_filesz;
    uint32_t p_memsz;
    uint32_t p_flags;
    uint32_t p_align;
  } Elf32_Phdr;

  /* ELF64 dynamic entry */
  typedef struct {
    int64_t d_tag;
    uint64_t d_val;
  } Elf64_Dyn;

  /* ELF32 dynamic entry */
  typedef struct {
    int32_t d_tag;
    uint32_t d_val;
  } Elf32_Dyn;

  /* Export sizes for JS */
  const uint32_t sizeof_Elf64_Dyn  = sizeof(Elf64_Dyn);
  const uint32_t sizeof_Elf32_Dyn  = sizeof(Elf32_Dyn);

  /* Offsets: Elf64_Ehdr */
  const uint32_t off_Elf64_Ehdr_e_type      = offsetof(Elf64_Ehdr, e_type);
  const uint32_t off_Elf64_Ehdr_e_machine   = offsetof(Elf64_Ehdr, e_machine);
  const uint32_t off_Elf64_Ehdr_e_phoff     = offsetof(Elf64_Ehdr, e_phoff);
  const uint32_t off_Elf64_Ehdr_e_phentsize = offsetof(Elf64_Ehdr, e_phentsize);
  const uint32_t off_Elf64_Ehdr_e_phnum     = offsetof(Elf64_Ehdr, e_phnum);

  /* Offsets: Elf32_Ehdr */
  const uint32_t off_Elf32_Ehdr_e_type      = offsetof(Elf32_Ehdr, e_type);
  const uint32_t off_Elf32_Ehdr_e_machine   = offsetof(Elf32_Ehdr, e_machine);
  const uint32_t off_Elf32_Ehdr_e_phoff     = offsetof(Elf32_Ehdr, e_phoff);
  const uint32_t off_Elf32_Ehdr_e_phentsize = offsetof(Elf32_Ehdr, e_phentsize);
  const uint32_t off_Elf32_Ehdr_e_phnum     = offsetof(Elf32_Ehdr, e_phnum);

  /* Offsets: Elf64_Phdr */
  const uint32_t off_Elf64_Phdr_p_type   = offsetof(Elf64_Phdr, p_type);
  const uint32_t off_Elf64_Phdr_p_flags  = offsetof(Elf64_Phdr, p_flags);
  const uint32_t off_Elf64_Phdr_p_offset = offsetof(Elf64_Phdr, p_offset);
  const uint32_t off_Elf64_Phdr_p_vaddr  = offsetof(Elf64_Phdr, p_vaddr);
  const uint32_t off_Elf64_Phdr_p_filesz = offsetof(Elf64_Phdr, p_filesz);
  const uint32_t off_Elf64_Phdr_p_memsz  = offsetof(Elf64_Phdr, p_memsz);

  /* Offsets: Elf32_Phdr */
  const uint32_t off_Elf32_Phdr_p_type   = offsetof(Elf32_Phdr, p_type);
  const uint32_t off_Elf32_Phdr_p_flags  = offsetof(Elf32_Phdr, p_flags);
  const uint32_t off_Elf32_Phdr_p_offset = offsetof(Elf32_Phdr, p_offset);
  const uint32_t off_Elf32_Phdr_p_vaddr  = offsetof(Elf32_Phdr, p_vaddr);
  const uint32_t off_Elf32_Phdr_p_filesz = offsetof(Elf32_Phdr, p_filesz);
  const uint32_t off_Elf32_Phdr_p_memsz  = offsetof(Elf32_Phdr, p_memsz);

  /* Offsets: Elf64_Dyn */
  const uint32_t off_Elf64_Dyn_d_tag = offsetof(Elf64_Dyn, d_tag);
  const uint32_t off_Elf64_Dyn_d_val = offsetof(Elf64_Dyn, d_val);

  /* Offsets: Elf32_Dyn */
  const uint32_t off_Elf32_Dyn_d_tag = offsetof(Elf32_Dyn, d_tag);
  const uint32_t off_Elf32_Dyn_d_val = offsetof(Elf32_Dyn, d_val);
`);

function C(name: string): number {
  return (cm as Record<string, NativePointer>)[name].readU32();
}

export interface PhdrInfo {
  type: number;
  flags: number;
  offset: UInt64;
  vaddr: UInt64;
  filesz: UInt64;
  memsz: UInt64;
}

export interface DynEntry {
  tag: number;
  val: number;
}

export interface ELFParsed {
  base: NativePointer;
  is64: boolean;
  eType: number;
  eMachine: number;
  phdrs: PhdrInfo[];
  dyn: DynEntry[];
  sections: ModuleSectionDetails[];
  symbols: ModuleSymbolDetails[];
  exports: ModuleExportDetails[];
  imports: ModuleImportDetails[];
  names: Set<string>;
}

export function parseELF(mod: Module): ELFParsed {
  const base = mod.base;

  if (base.readU32() !== ELFMAG) {
    throw new Error("not an ELF file");
  }

  if (base.add(5).readU8() === ELFDATA2MSB) {
    throw new Error("big-endian ELF not supported");
  }

  const is64 = base.add(4).readU8() === ELFCLASS64;

  let eType: number, eMachine: number;
  if (is64) {
    eType = base.add(C("off_Elf64_Ehdr_e_type")).readU16();
    eMachine = base.add(C("off_Elf64_Ehdr_e_machine")).readU16();
  } else {
    eType = base.add(C("off_Elf32_Ehdr_e_type")).readU16();
    eMachine = base.add(C("off_Elf32_Ehdr_e_machine")).readU16();
  }

  const phdrs = parsePhdrs(base, is64);
  const dyn = parseDynamic(base, is64, phdrs);

  const sections = mod.enumerateSections();
  const symbols = mod.enumerateSymbols();
  const exports = mod.enumerateExports();
  const imports = mod.enumerateImports();

  const names = new Set<string>();
  for (const e of exports) names.add(e.name);
  for (const i of imports) names.add(i.name);

  return {
    base,
    is64,
    eType,
    eMachine,
    phdrs,
    dyn,
    sections,
    symbols,
    exports,
    imports,
    names,
  };
}

function parsePhdrs(base: NativePointer, is64: boolean): PhdrInfo[] {
  let phoff: UInt64, phentsize: number, phnum: number;
  if (is64) {
    phoff = base.add(C("off_Elf64_Ehdr_e_phoff")).readU64();
    phentsize = base.add(C("off_Elf64_Ehdr_e_phentsize")).readU16();
    phnum = base.add(C("off_Elf64_Ehdr_e_phnum")).readU16();
  } else {
    phoff = uint64(base.add(C("off_Elf32_Ehdr_e_phoff")).readU32());
    phentsize = base.add(C("off_Elf32_Ehdr_e_phentsize")).readU16();
    phnum = base.add(C("off_Elf32_Ehdr_e_phnum")).readU16();
  }

  const phdrs: PhdrInfo[] = [];
  for (let i = 0; i < phnum && i < 10000; i++) {
    const ph = base.add(phoff.add(i * phentsize));
    if (is64) {
      phdrs.push({
        type: ph.add(C("off_Elf64_Phdr_p_type")).readU32(),
        flags: ph.add(C("off_Elf64_Phdr_p_flags")).readU32(),
        offset: ph.add(C("off_Elf64_Phdr_p_offset")).readU64(),
        vaddr: ph.add(C("off_Elf64_Phdr_p_vaddr")).readU64(),
        filesz: ph.add(C("off_Elf64_Phdr_p_filesz")).readU64(),
        memsz: ph.add(C("off_Elf64_Phdr_p_memsz")).readU64(),
      });
    } else {
      phdrs.push({
        type: ph.add(C("off_Elf32_Phdr_p_type")).readU32(),
        flags: ph.add(C("off_Elf32_Phdr_p_flags")).readU32(),
        offset: uint64(ph.add(C("off_Elf32_Phdr_p_offset")).readU32()),
        vaddr: uint64(ph.add(C("off_Elf32_Phdr_p_vaddr")).readU32()),
        filesz: uint64(ph.add(C("off_Elf32_Phdr_p_filesz")).readU32()),
        memsz: uint64(ph.add(C("off_Elf32_Phdr_p_memsz")).readU32()),
      });
    }
  }
  return phdrs;
}

function parseDynamic(
  base: NativePointer,
  is64: boolean,
  phdrs: PhdrInfo[],
): DynEntry[] {
  const entries: DynEntry[] = [];
  for (const ph of phdrs) {
    if (ph.type !== PT_DYNAMIC) continue;
    const dynBase = base.add(ph.offset);
    const entSize = is64 ? C("sizeof_Elf64_Dyn") : C("sizeof_Elf32_Dyn");
    const count = (ph.filesz.toNumber() / entSize) | 0;
    for (let i = 0; i < count; i++) {
      const p = dynBase.add(i * entSize);
      let tag: number, val: number;
      if (is64) {
        tag = p.add(C("off_Elf64_Dyn_d_tag")).readS64().toNumber();
        val = p.add(C("off_Elf64_Dyn_d_val")).readU64().toNumber();
      } else {
        tag = p.add(C("off_Elf32_Dyn_d_tag")).readU32();
        val = p.add(C("off_Elf32_Dyn_d_val")).readU32();
      }
      if (tag === 0) break; // DT_NULL
      entries.push({ tag, val });
    }
    break;
  }
  return entries;
}

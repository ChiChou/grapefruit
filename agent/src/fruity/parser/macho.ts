const MH_MAGIC_64 = 0xfeedfacf;
const MH_CIGAM_64 = 0xcffaedfe;
const MH_MAGIC = 0xfeedface;
const MH_CIGAM = 0xcefaedfe;

const cm = new CModule(`
  #include <stdint.h>
  #include <stddef.h>

  typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
  } mach_header;

  typedef struct {
    uint32_t magic;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint32_t flags;
    uint32_t reserved;
  } mach_header_64;

  typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
  } load_command;

  typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    uint32_t pad;
  } encryption_info_command_64;

  typedef struct {
    uint32_t cmd;
    uint32_t cmdsize;
    uint32_t path_offset;
  } rpath_command;

  const uint32_t sizeof_mach_header_64    = sizeof(mach_header_64);

  const uint32_t off_mh64_filetype        = offsetof(mach_header_64, filetype);
  const uint32_t off_mh64_ncmds           = offsetof(mach_header_64, ncmds);
  const uint32_t off_mh64_flags           = offsetof(mach_header_64, flags);

  const uint32_t off_lc_cmd               = offsetof(load_command, cmd);
  const uint32_t off_lc_cmdsize           = offsetof(load_command, cmdsize);

  const uint32_t off_enc_cryptoff         = offsetof(encryption_info_command_64, cryptoff);
  const uint32_t off_enc_cryptsize        = offsetof(encryption_info_command_64, cryptsize);
  const uint32_t off_enc_cryptid          = offsetof(encryption_info_command_64, cryptid);
  const uint32_t off_rpath_path_offset    = offsetof(rpath_command, path_offset);
`);

const cmExports = cm as Record<string, NativePointer>;

function C(name: string): number {
  return cmExports[name].readU32();
}

export interface LoadCommand {
  cmd: number;
  cmdsize: number;
  ptr: NativePointer;
}

export interface MachOParsed {
  fileType: number;
  flags: number;
  loadCommands: LoadCommand[];
  sections: ModuleSectionDetails[];
  symbols: ModuleSymbolDetails[];
  exports: ModuleExportDetails[];
  imports: ModuleImportDetails[];
  names: Set<string>;
}

export function parseMachO(mod: Module): MachOParsed {
  const base = mod.base;
  const magic = base.readU32();

  if (magic === MH_CIGAM_64 || magic === MH_CIGAM)
    throw new Error("Big-endian system is not supported");
  if (magic === MH_MAGIC) throw new Error("32-bit Mach-O is not supported");
  if (magic !== MH_MAGIC_64) throw new Error("Not a Mach-O file");

  const fileType = base.add(C("off_mh64_filetype")).readU32();
  const ncmds = base.add(C("off_mh64_ncmds")).readU32();
  const flags = base.add(C("off_mh64_flags")).readU32();

  const loadCommands = parseLoadCommands(
    base.add(C("sizeof_mach_header_64")),
    ncmds,
  );

  const sections = mod.enumerateSections();
  const symbols = mod.enumerateSymbols();
  const exports = mod.enumerateExports();
  const imports = mod.enumerateImports();

  const names = new Set<string>();
  for (const e of exports) names.add(e.name);
  for (const i of imports) names.add(i.name);

  return {
    fileType,
    flags,
    loadCommands,
    sections,
    symbols,
    exports,
    imports,
    names,
  };
}

function parseLoadCommands(start: NativePointer, ncmds: number): LoadCommand[] {
  const commands: LoadCommand[] = [];
  let p = start;
  for (let i = 0; i < ncmds; i++) {
    const cmd = p.add(C("off_lc_cmd")).readU32();
    const cmdsize = p.add(C("off_lc_cmdsize")).readU32();
    commands.push({ cmd, cmdsize, ptr: p });
    p = p.add(cmdsize);
  }
  return commands;
}

export interface EncryptionInfo {
  cryptoff: number;
  cryptsize: number;
  cryptid: number;
}

export function readEncryptionInfo(lc: LoadCommand): EncryptionInfo {
  return {
    cryptoff: lc.ptr.add(C("off_enc_cryptoff")).readU32(),
    cryptsize: lc.ptr.add(C("off_enc_cryptsize")).readU32(),
    cryptid: lc.ptr.add(C("off_enc_cryptid")).readU32(),
  };
}

export function readRpath(lc: LoadCommand): string {
  const offset = lc.ptr.add(C("off_rpath_path_offset")).readU32();
  const rpath = lc.ptr.add(offset).readUtf8String() ?? "";
  return rpath.replace(/\0+$/, "");
}

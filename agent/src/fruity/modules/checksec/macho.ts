import {
  parseMachO,
  readEncryptionInfo,
  readRpath,
  type MachOParsed,
} from "../../parser/macho.js";

// Used by Mach-O checksec
export interface MachOResult {
  pie: boolean;
  nx: boolean | string;
  canary: boolean;
  arc: boolean;
  rpath: string[];
  codesign: boolean;
  encryption: boolean | string;
  stripped: boolean;
  fortify: { fortified: number; fortifiable: number };
  pac: false | string;
}

const MH_EXECUTE = 0x2;

const MH_PIE = 0x200000;
const MH_NO_HEAP_EXECUTION = 0x1000000;
const MH_ALLOW_STACK_EXECUTION = 0x20000;

const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const LC_CODE_SIGNATURE = 0x1d;
const LC_RPATH = 0x8000001c;

function checkCanary(macho: MachOParsed): boolean {
  const valid = (s: ModuleSymbolDetails | ModuleImportDetails) => {
    return s.name === "___stack_chk_fail" || s.name === "___stack_chk_guard";
  };

  return macho.symbols.some(valid) || macho.imports.some(valid);
}

function checkARC(macho: MachOParsed): boolean {
  const arcSymbols = new Set([
    "objc_autorelease",
    "objc_autoreleasePoolPop",
    "objc_autoreleasePoolPush",
    "objc_autoreleaseReturnValue",
    "objc_copyWeak",
    "objc_destroyWeak",
    "objc_initWeak",
    "objc_loadWeak",
    "objc_loadWeakRetained",
    "objc_moveWeak",
    "objc_release",
    "objc_retain",
    "objc_retainAutorelease",
    "objc_retainAutoreleaseReturnValue",
    "objc_retainAutoreleasedReturnValue",
    "objc_retainBlock",
    "objc_storeStrong",
    "objc_storeWeak",
    "objc_unsafeClaimAutoreleasedReturnValue",
  ]);

  for (const s of macho.imports) {
    if (s.module === "/usr/lib/libobjc.A.dylib" && arcSymbols.has(s.name))
      return true;
  }
  return false;
}

function getRpaths(macho: MachOParsed): string[] {
  const rpaths: string[] = [];
  for (const lc of macho.loadCommands) {
    if (lc.cmd === LC_RPATH) {
      rpaths.push(readRpath(lc));
    }
  }
  return rpaths;
}

function hasLoadCommand(macho: MachOParsed, target: number): boolean {
  return macho.loadCommands.some((lc) => lc.cmd === target);
}

function getEncryption(macho: MachOParsed): boolean | string {
  for (const lc of macho.loadCommands) {
    if (lc.cmd === LC_ENCRYPTION_INFO_64 || lc.cmd === LC_ENCRYPTION_INFO) {
      const enc = readEncryptionInfo(lc);
      return enc.cryptid !== 0 ? true : "header only";
    }
  }
  return false;
}

function getFortify(macho: MachOParsed): {
  fortified: number;
  fortifiable: number;
} {
  const base = [
    "_memcpy",
    "_memmove",
    "_memset",
    "_stpcpy",
    "_stpncpy",
    "_strcat",
    "_strcpy",
    "_strncat",
    "_strncpy",
    "_snprintf",
    "_sprintf",
    "_vsnprintf",
    "_vsprintf",
  ];
  const chk = base.map((n) => `_${n}_chk`);
  let fortified = 0;
  let fortifiable = 0;
  for (const chkName of chk) {
    if (macho.names.has(chkName)) fortified++;
  }
  for (let i = 0; i < base.length; i++) {
    if (macho.names.has(base[i]) || macho.names.has(chk[i])) {
      fortifiable++;
    }
  }
  return { fortified, fortifiable };
}

function getPAC(macho: MachOParsed): false | string {
  if (Process.arch !== "arm64") return false;
  const authSections = new Set(["__auth_stubs", "__auth_got", "__auth_ptr"]);
  const found: string[] = [];
  for (const sect of macho.sections) {
    if (authSections.has(sect.name) && !found.includes(sect.name)) {
      found.push(sect.name);
    }
  }
  return found.length > 0 ? found.join(", ") : false;
}

export default function checksec(mod: Module): MachOResult {
  const macho = parseMachO(mod);
  return {
    pie: macho.fileType !== MH_EXECUTE || !!(macho.flags & MH_PIE),
    nx:
      macho.flags & MH_ALLOW_STACK_EXECUTION
        ? false
        : macho.flags & MH_NO_HEAP_EXECUTION
          ? "stack + heap"
          : true,
    canary: checkCanary(macho),
    arc: checkARC(macho),
    rpath: getRpaths(macho),
    codesign: hasLoadCommand(macho, LC_CODE_SIGNATURE),
    encryption: getEncryption(macho),
    stripped: macho.symbols.length === 0,
    fortify: getFortify(macho),
    pac: getPAC(macho),
  };
}

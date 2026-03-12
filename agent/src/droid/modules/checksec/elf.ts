// this implementation is inspired by checksec.sh project
// https://github.com/slimm609/checksec?tab=License-1-ov-file

// The BSD License (http://www.opensource.org/licenses/bsd-license.php)
// specifies the terms and conditions of use for checksec.sh:
// Copyright (c) 2014-2022, Brian Davis
// Copyright (c) 2013, Robin David
// Copyright (c) 2009-2011, Tobias Klein
// All rights reserved.
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions
// are met:
//   * Redistributions of source code must retain the above copyright
//     notice, this list of conditions and the following disclaimer.
//   * Redistributions in binary form must reproduce the above copyright
//     notice, this list of conditions and the following disclaimer in
//     the documentation and/or other materials provided with the
//     distribution.
//   * Neither the name of Tobias Klein nor the name of trapkit.de may be
//     used to endorse or promote products derived from this software
//     without specific prior written permission.
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
// "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
// LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
// FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
// COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
// INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
// BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
// OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED
// AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
// OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
// THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
// DAMAGE.

import { parseELF, type ELFParsed } from "../../parser/elf.js";

// Used by ELF checksec
export interface ELFResult {
  relro: "full" | "partial" | "none";
  nx: boolean;
  pie: boolean | "rel";
  canary: boolean;
  rpath: boolean;
  runpath: boolean;
  stripped: boolean;
  fortify: { fortified: number; fortifiable: number };
  safeStack: boolean;
  cfi: ELFCFI;
}

export interface ELFCFI {
  clang: "none" | "single" | "multi";
  shstk?: boolean;
  ibt?: boolean;
  pac?: boolean;
  bti?: boolean;
}

// e_type
const ET_REL = 1;
const ET_DYN = 3;

// e_machine
const EM_X86_64 = 62;
const EM_AARCH64 = 183;

// p_type
const PT_NOTE = 4;
const PT_GNU_STACK = 0x6474e551;
const PT_GNU_RELRO = 0x6474e552;

// p_flags
const PF_X = 0x1;

// d_tag
const DT_RPATH = 15;
const DT_BIND_NOW = 24;
const DT_RUNPATH = 29;
const DT_FLAGS = 30;
const DT_FLAGS_1 = 0x6ffffffb;

// d_flags
const DF_BIND_NOW = 0x8;
const DF_1_NOW = 0x1;

// GNU property note types
const NT_GNU_PROPERTY_TYPE_0 = 5;
const GNU_PROPERTY_X86_FEATURE_1_AND = 0xc0000002;
const GNU_PROPERTY_X86_FEATURE_1_IBT = 1;
const GNU_PROPERTY_X86_FEATURE_1_SHSTK = 2;
const GNU_PROPERTY_AARCH64_FEATURE_1_AND = 0xc0000000;
const GNU_PROPERTY_AARCH64_FEATURE_1_BTI = 1;
const GNU_PROPERTY_AARCH64_FEATURE_1_PAC = 2;

function dynValues(elf: ELFParsed, tag: number): number[] {
  return elf.dyn.filter((e) => e.tag === tag).map((e) => e.val);
}

function hasSymbol(elf: ELFParsed, prefix: string): boolean {
  for (const s of elf.symbols) {
    if (s.name.startsWith(prefix)) return true;
  }
  for (const s of elf.imports) {
    if (s.name.startsWith(prefix)) return true;
  }
  return false;
}

function checkRelro(elf: ELFParsed): ELFResult["relro"] {
  const hasRelroSeg = elf.phdrs.some((p) => p.type === PT_GNU_RELRO);
  if (!hasRelroSeg) return "none";

  const bind = dynValues(elf, DT_BIND_NOW);
  const flags = dynValues(elf, DT_FLAGS);
  const flags1 = dynValues(elf, DT_FLAGS_1);

  const bindNow =
    bind.length > 0 ||
    (flags.length > 0 && (flags[0] & DF_BIND_NOW) !== 0) ||
    (flags1.length > 0 && (flags1[0] & DF_1_NOW) !== 0);

  return bindNow ? "full" : "partial";
}

function checkNX(elf: ELFParsed): boolean {
  for (const ph of elf.phdrs) {
    if (ph.type === PT_GNU_STACK) return (ph.flags & PF_X) === 0;
  }
  return false;
}

function checkPIE(elf: ELFParsed): boolean | "rel" {
  if (elf.eType === ET_DYN) return true;
  if (elf.eType === ET_REL) return "rel";
  return false;
}

function checkFortify(elf: ELFParsed): {
  fortified: number;
  fortifiable: number;
} {
  const FORTIFY_BASE = [
    "memcpy",
    "memmove",
    "mempcpy",
    "memset",
    "stpcpy",
    "stpncpy",
    "strcat",
    "strcpy",
    "strncat",
    "strncpy",
    "snprintf",
    "sprintf",
    "vsnprintf",
    "vsprintf",
    "fprintf",
    "printf",
    "vfprintf",
    "vprintf",
  ];
  const FORTIFY_CHK = FORTIFY_BASE.map((n) => `__${n}_chk`);

  let fortified = 0;
  let fortifiable = 0;
  for (const chkName of FORTIFY_CHK) {
    if (elf.names.has(chkName)) fortified++;
  }
  for (let i = 0; i < FORTIFY_BASE.length; i++) {
    if (elf.names.has(FORTIFY_BASE[i]) || elf.names.has(FORTIFY_CHK[i])) {
      fortifiable++;
    }
  }
  return { fortified, fortifiable };
}

function checkCFI(elf: ELFParsed): ELFCFI {
  const result: ELFCFI = { clang: "none" };

  // Find .note.gnu.property via Frida's section API
  let noteData: NativePointer | null = null;
  let noteSize = 0;

  const gnuProp = elf.sections.find((s) => s.name === ".note.gnu.property");
  if (gnuProp && !gnuProp.address.isNull()) {
    noteData = gnuProp.address;
    noteSize = gnuProp.size;
  }

  // Fallback: scan PT_NOTE segments
  if (!noteData) {
    for (const ph of elf.phdrs) {
      if (ph.type !== PT_NOTE) continue;
      const noteBase = elf.base.add(ph.offset);
      const noteLimit = ph.filesz.toNumber();
      let off = 0;
      while (off + 12 <= noteLimit) {
        const namesz = noteBase.add(off).readU32();
        const descsz = noteBase.add(off + 4).readU32();
        const ntype = noteBase.add(off + 8).readU32();
        const alignedNamesz = (namesz + 3) & ~3;
        const alignedDescsz = (descsz + 3) & ~3;
        if (ntype === NT_GNU_PROPERTY_TYPE_0 && namesz === 4) {
          const noteName = noteBase.add(off + 12).readCString(4) ?? "";
          if (noteName === "GNU") {
            noteData = noteBase.add(off + 12 + alignedNamesz);
            noteSize = descsz;
            break;
          }
        }
        off += 12 + alignedNamesz + alignedDescsz;
      }
      if (noteData) break;
    }
  }

  if (noteData && noteSize > 0) {
    let propData: NativePointer;
    let propSize: number;

    // Check if starts with note header (namesz=4 for "GNU\0")
    const firstU32 = noteData.readU32();
    if (firstU32 === 4) {
      const descsz = noteData.add(4).readU32();
      const alignedNamesz = (firstU32 + 3) & ~3;
      propData = noteData.add(12 + alignedNamesz);
      propSize = descsz;
    } else {
      propData = noteData;
      propSize = noteSize;
    }

    const propAlign = elf.is64 ? 8 : 4;

    if (elf.is64 && elf.eMachine === EM_X86_64) {
      let i = 0;
      while (i + 8 <= propSize) {
        const noteType = propData.add(i).readU32();
        const datasz = propData.add(i + 4).readU32();
        i += 8;
        if (datasz === 4 && i + 4 <= propSize) {
          const bitmask = propData.add(i).readU32();
          if (noteType === GNU_PROPERTY_X86_FEATURE_1_AND) {
            result.ibt = (bitmask & GNU_PROPERTY_X86_FEATURE_1_IBT) !== 0;
            result.shstk = (bitmask & GNU_PROPERTY_X86_FEATURE_1_SHSTK) !== 0;
          }
        }
        i += (datasz + propAlign - 1) & ~(propAlign - 1);
      }
    } else if (elf.is64 && elf.eMachine === EM_AARCH64) {
      let i = 0;
      while (i + 8 <= propSize) {
        const noteType = propData.add(i).readU32();
        const datasz = propData.add(i + 4).readU32();
        i += 8;
        if (datasz === 4 && i + 4 <= propSize) {
          const bitmask = propData.add(i).readU32();
          if (noteType === GNU_PROPERTY_AARCH64_FEATURE_1_AND) {
            result.bti = (bitmask & GNU_PROPERTY_AARCH64_FEATURE_1_BTI) !== 0;
            result.pac = (bitmask & GNU_PROPERTY_AARCH64_FEATURE_1_PAC) !== 0;
          }
        }
        i += (datasz + propAlign - 1) & ~(propAlign - 1);
      }
    }
  }

  // Clang CFI detection
  for (const e of elf.exports) {
    if (e.name === "__cfi_check") {
      result.clang = "multi";
      return result;
    }
  }

  const CFINames = new Set([
    "__CFI_check",
    "__CFI_slowpath",
    "__CFI_slowpath_diag",
    "__CFI_fail",
    "__CFI_check_fail",
  ]);
  for (const s of elf.symbols) {
    if (s.section === undefined) continue;
    if (CFINames.has(s.name)) {
      result.clang = "single";
      break;
    }
  }

  return result;
}

export default function checksec(mod: Module): ELFResult {
  const elf = parseELF(mod);
  return {
    relro: checkRelro(elf),
    canary:
      hasSymbol(elf, "__stack_chk_fail") || hasSymbol(elf, "__stack_chk_guard"),
    nx: checkNX(elf),
    pie: checkPIE(elf),
    rpath: dynValues(elf, DT_RPATH).length > 0,
    runpath: dynValues(elf, DT_RUNPATH).length > 0,
    stripped: !elf.sections.some((s) => s.name === ".symtab"),
    fortify: checkFortify(elf),
    safeStack: hasSymbol(elf, "__safestack_init"),
    cfi: checkCFI(elf),
  };
}

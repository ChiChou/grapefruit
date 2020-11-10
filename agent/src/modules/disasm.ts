import c from '../../gen/macho.c'

interface Section {
  name?: string;
  floor: NativePointer;
  ceil: NativePointer;
}

function maps() {
  const uintptr_t = Process.pointerSize === 8 ? 'int64' : 'long'
  const cm = new CModule(c)
  const sections = new NativeFunction(cm.sections, 'void', ['pointer', 'pointer'])
  const vmmap: Section[] = []

  for (const mod of Process.enumerateModules()) {
    const cb = new NativeCallback((sectname: NativePointer, base: NativeArgumentValue, top: NativeArgumentValue) => {
      const name = sectname.readCString()?.slice(0, 16)
      const floor = ptr(base.toString())
      const ceil = ptr(top.toString())
      vmmap.push({ name, floor, ceil })
    }, 'void', ['pointer', uintptr_t, uintptr_t])

    sections(mod.base, cb)
  }

  return vmmap
}

type StringReader = (p: NativePointer) => string | null
type Readers = { [section: string]: StringReader }

const readers: Readers = {
  __cstring: p => `"${p.readCString()}"`,
  __cfstring: p => `@"${p.add(Process.pointerSize * 2).readPointer().readCString()}"`,
  __objc_methtype: p => p.readCString(),
  __objc_methname: p => p.readCString(),
  __objc_selrefs: p => `@selector(${p.add(Process.pointerSize * 2).readPointer().readCString()})`,
  __la_symbol_ptr: p => DebugSymbol.fromAddress(p.readPointer()).name,
  __la_resolver: p => DebugSymbol.fromAddress(p.readPointer()).name,
  __objc_classrefs: p => `_OBJC_CLASS_$_${new ObjC.Object(p.readPointer())}`,
  __objc_superrefs: p => `_OBJC_CLASS_$_${new ObjC.Object(p.readPointer())}`,
  __objc_protorefs: p => `_OBJC_PROTOCOL_$_${new ObjC.Protocol(p.readPointer())}`,
  __ustring: p => `u"${p.readUtf16String()}"`
}

export default function disasm(addr: string | number, count = 100) {
  if (!new Set(['arm', 'arm64']).has(Process.arch)) throw new Error('CPU not supported')

  let p = ptr(addr).strip()
  if (p.isNull()) throw new Error(`Invalid address ${addr}`)

  const symbol = DebugSymbol.fromAddress(p).name
  const range = Process.findRangeByAddress(p)
  if (!range) throw new Error(`Address ${p} is not mapped`)
  if (range.protection.indexOf('x') === -1) throw new Error(`${p} is not executable`)

  const vmmap = maps()
  function readable(p: NativePointer) {
    for (const sect of vmmap) {
      if (sect.floor.compare(p) <= 0 && sect.ceil.compare(p) > 0) {
        console.log(`[debug] ${p} is in ${sect.name}`)
        if (!sect.name || typeof readers[sect.name] !== 'function') return undefined
        return readers[sect.name](p)
      }
    }
    console.log(`[debug] range not found for ${p}`)
    if (Process.findRangeByAddress(p)?.protection === 'r-x') {
      try {
        return p.readCString()
      } catch (_) {

      }
    }
  }

  const end = range.base.add(range.size)
  function* gen() {
    let prev: ArmInstruction | Arm64Instruction | undefined
    for (let i = 0; i < count; i++) {
      const insn = Instruction.parse(p) as ArmInstruction | Arm64Instruction
      if (!insn) return
      const { opStr, address, groups, operands, mnemonic, regsRead, regsWritten } = insn
      let comment, symbol

      if (groups.indexOf('jump') > -1) {
        for (const op of operands) {
          if (op.type === 'imm') {
            const sym = DebugSymbol.fromAddress(ptr(op.value.toString()))
            if (!sym?.name?.match(/^0x\d+/)) {
              if (operands.length === 1) {
                symbol = sym.name
              }
              comment = sym.name
            }
          }
        }
      }

      if (prev && prev.mnemonic === 'adrp' && prev.operands[1]?.type === 'imm') {
        const base = ptr(prev.operands[1].value.toString())
        if (insn.mnemonic === 'ldr') {
          const op2 = insn.operands[1]
          if (op2?.type === 'mem') {
            const { value } = op2 as ArmMemOperand | Arm64MemOperand
            if (value.base === prev.operands[0].value) {
              const p = base.add(value.disp)
              comment = readable(p)
            }
          }
        } else if (insn.mnemonic == 'add') {
          const op3 = insn.operands[2]
          if (op3?.type === 'imm') {
            const { value } = op3 as ArmImmOperand | Arm64ImmOperand
            const p = base.add(value)
            // console.log(p.toString())
            comment = readable(p)
            // console.log(JSON.stringify(insn))
          }
        }
      } else if (insn.mnemonic === 'ldr' && prev?.mnemonic === 'nop') {
        const op2 = insn.operands[1]
        if (op2?.type === 'imm') {
          const { value } = op2 as ArmImmOperand | Arm64ImmOperand
          const p = ptr(value.toString())
          comment = readable(p)
        }
      }

      const string = insn.toString()
      yield { opStr, address, groups, mnemonic, operands, regsRead, regsWritten, string, comment, symbol }
      prev = insn

      p = insn.next
      if (!p || p.isNull()) return
      if (p.compare(end) > -1) return
    }
  }

  return {
    symbol,
    instructions: [...gen()],
  }
}

export default function disasm(addr: string | number, count=100) {
  if (!new Set(['arm', 'arm64']).has(Process.arch)) throw new Error('CPU not supported')

  let p = ptr(addr)
  if (p.isNull()) throw new Error(`Invalid address ${addr}`)

  const range = Process.findRangeByAddress(p)
  if (!range) throw new Error(`Address ${p} is not mapped`)
  if (range.protection.indexOf('x') === -1) throw new Error(`${p} is not executable`)

  const end = range.base.add(range.size)
  function * gen() {
    for (let i = 0; i < count; i++) {
      const insn = Instruction.parse(p) as ArmInstruction | Arm64Instruction
      if (!insn) return
      const { opStr, address, groups, operands, mnemonic, regsRead, regsWritten } = insn
      let comment

      if (groups.indexOf('jump') > -1) {
        for (const op of operands) {
          if (op.type === 'imm') {
            const sym = DebugSymbol.fromAddress(ptr(op.value.toString()))
            comment = sym.name
          }
        }
      }

      const string = insn.toString()
      yield { opStr, address, groups, mnemonic, operands, regsRead, regsWritten, string, comment }

      p = insn.next
      if (!p || p.isNull()) return
      if (p.compare(end) > -1) return
    }
  }

  return [...gen()]
}

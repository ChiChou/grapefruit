import { dictFromPlistCharArray } from '../lib/dict'
import { encryptionInfo, pie } from '../lib/macho'


export default function checksec() {
  const [main] = Process.enumerateModules()
  const info = encryptionInfo(main)
  const imports = new Set(main.enumerateImports().map(i => i.name))
  const result = {
    pie: pie(main),
    encrypted: !encryptionInfo(main).ptr.isNull(),
    canary: imports.has('__stack_chk_guard'),
    arc: imports.has('objc_release'),
    entitlements: {}
  }

  const CS_OPS_ENTITLEMENTS_BLOB = 7
  const csops = new NativeFunction(
    Module.findExportByName('libsystem_kernel.dylib', 'csops')!,
    'int',
    ['int', 'int', 'pointer', 'uint64']
  )

  // struct csheader {
  //   uint32_t magic;
  //   uint32_t length;
  // };

  const SIZE_OF_CSHEADER = 8
  const csheader = Memory.alloc(SIZE_OF_CSHEADER)
  if (csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, csheader, SIZE_OF_CSHEADER) === -1) {
    const length = csheader.add(4).readU32()
    const content = Memory.alloc(length)
    if (csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, content, length) === 0) {
      result.entitlements = dictFromPlistCharArray(
        content.add(SIZE_OF_CSHEADER), length - SIZE_OF_CSHEADER
      )
    }
  }

  return result
}

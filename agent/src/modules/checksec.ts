import { dictFromBytes } from '../lib/dict.js'
import { encryptionInfo, pie } from '../lib/macho.js'


export default function checksec() {
  const [main] = Process.enumerateModules()
  const imports = new Set(main.enumerateImports().map(i => i.name))
  const result = {
    pie: pie(main),
    encrypted: !encryptionInfo(main)?.ptr.isNull(),
    canary: imports.has('__stack_chk_guard'),
    arc: imports.has('objc_release'),
    entitlements: {}
  }

  const CS_OPS_ENTITLEMENTS_BLOB = 7
  const libsystem_kernel = Process.findModuleByName('libsystem_kernel.dylib');
  if (!libsystem_kernel)
    return {};

  const impl = libsystem_kernel.findExportByName('csops');
  if (!impl)
    return {};

  const csops = new SystemFunction(
    impl,
    'int',
    ['int', 'int', 'pointer', 'ulong']
  )

  // todo: determine CPU endianness
  const ntohl = (val: number) => ((val & 0xFF) << 24)
    | ((val & 0xFF00) << 8)
    | ((val >> 8) & 0xFF00)
    | ((val >> 24) & 0xFF);

  // struct csheader {
  //   uint32_t magic;
  //   uint32_t length;
  // };

  const SIZE_OF_CSHEADER = 8
  const ERANGE = 34
  const csheader = Memory.alloc(SIZE_OF_CSHEADER)
  const { value, errno } = csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, csheader, SIZE_OF_CSHEADER) as UnixSystemFunctionResult<number>
  if (value === -1 && errno === ERANGE) {
    const length = ntohl(csheader.add(4).readU32())
    const content = Memory.alloc(length)
    if (csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, content, length).value === 0) {
      result.entitlements = dictFromBytes(
        content.add(SIZE_OF_CSHEADER), length - SIZE_OF_CSHEADER
      )
    }
  }

  return result
}

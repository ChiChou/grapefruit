import { fromBytes } from '../bridge/dictionary.js';
import { encryptionInfo, pie } from '../lib/macho.js';

export interface Entitlements {
  [key: string]: string | boolean | number | string[];
}

export interface CheckSecFlags {
  pie: boolean;
  arc: boolean;
  canary: boolean;
  encrypted: boolean;
}

export function flags(): CheckSecFlags {
  const [main,] = Process.enumerateModules()
  const uniqueNames = new Set(main.enumerateImports().map(({ name }) => name))

  return {
    pie: pie(main),
    arc: uniqueNames.has('objc_release'),
    canary: uniqueNames.has('__stack_chk_guard'),
    encrypted: encryptionInfo(main)?.cryptid === 1
  }
}

export function entitlements(): Entitlements {
  const CS_OPS_ENTITLEMENTS_BLOB = 7
  const csops = new SystemFunction(
    Module.findExportByName('libsystem_kernel.dylib', 'csops')!,
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
  const result = csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, csheader, SIZE_OF_CSHEADER)
  const { value, errno } = result as UnixSystemFunctionResult<number>
  if (value === -1 && errno === ERANGE) {
    const length = ntohl(csheader.add(4).readU32())
    const content = Memory.alloc(length)
    if (csops(Process.id, CS_OPS_ENTITLEMENTS_BLOB, content, length).value === 0) {
      return fromBytes(content.add(SIZE_OF_CSHEADER), length - SIZE_OF_CSHEADER) as Entitlements
    }
  }

  return {}
}

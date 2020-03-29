import c from '../../gen/macho.c'

type EncryptInfoTuple = [NativePointer, number, number, number, number]
const EncryptInfoTuple = ['pointer', 'uint32', 'uint32', 'uint32', 'uint32']

interface EncryptInfo {
  ptr: NativePointer;
  offset: number;
  size: number;
  offsetOfCmd: number;
  sizeOfCmd: number;
}

const cm = new CModule(c)

export function encryptionInfo(mod: Module): EncryptInfo {  
  const findEncyptInfo = new NativeFunction(cm['find_encryption_info'], EncryptInfoTuple, ['pointer'])
  const info = findEncyptInfo!(mod.base) as EncryptInfoTuple
  return {
    ptr: info[0],
    offset: info[1],
    size: info[2],
    offsetOfCmd: info[3],
    sizeOfCmd: info[4]
  }
}

export function pie(mod: Module): boolean {
  const isPie = new NativeFunction(cm['pie'], 'int', ['pointer'])
  return Boolean(isPie(mod.base))
}

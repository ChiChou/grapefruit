import { valueOf } from './dict'
import CF from '../api/CoreFoundation'

function wrap(name: string) {
  return function () {
    const func = new NativeFunction(Module.findExportByName(null, name)!, 'pointer', [])
    const result = func() as NativePointer
    return new ObjC.Object(result).toString()
  }
}

// todo: move to api/Foundation.ts
export const NSTemporaryDirectory = wrap('NSTemporaryDirectory')
export const NSHomeDirectory = wrap('NSHomeDirectory')


export function CFSTR(p: NativePointer) {
  const kCFStringEncodingUTF8 = 0x08000100
  const str = CF.CFStringGetCStringPtr(p, kCFStringEncodingUTF8) as NativePointer
  return str.readUtf8String(CF.CFStringGetLength(p) as number)
}

export function attrs(path: string) {
  const { NSFileManager, NSString } = ObjC.classes
  const pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
  const attr = NSFileManager.defaultManager()
    .attributesOfItemAtPath_error_(NSString.stringWithString_(path), pError)

  const err = pError.readPointer()
  if (!err.isNull())
    throw new Error(new ObjC.Object(err).localizedDescription())

  const result: { [key: string]: string | number } = {}
  const lookup = {
    owner: 'NSFileOwnerAccountName',
    size: 'NSFileSize',
    creation: 'NSFileCreationDate',
    permission: 'NSFilePosixPermissions',
    type: 'NSFileType',
    group: 'NSFileGroupOwnerAccountName',
    modification: 'NSFileModificationDate',
    protection: 'NSFileProtectionKey'
  }

  for (const [jsKey, ocKey] of Object.entries(lookup))
    result[jsKey] = valueOf(attr.objectForKey_(ocKey))

  return result
}

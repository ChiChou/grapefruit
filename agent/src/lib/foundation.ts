import { valueOf } from './dict.js'

const CFStringGetCStringPtr = new NativeFunction(
  Module.findExportByName('CoreFoundation', 'CFStringGetCStringPtr')!, 'pointer', ['pointer', 'int']);
const CFStringGetLength = new NativeFunction(
  Module.findExportByName('CoreFoundation', 'CFStringGetLength')!, 'int', ['pointer']);

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
  const str = CFStringGetCStringPtr(p, kCFStringEncodingUTF8) as NativePointer
  return str.readUtf8String(CFStringGetLength(p) as number)
}

const attributeLookup = {
  owner: 'NSFileOwnerAccountName',
  size: 'NSFileSize',
  creation: 'NSFileCreationDate',
  permission: 'NSFilePosixPermissions',
  type: 'NSFileType',
  group: 'NSFileGroupOwnerAccountName',
  modification: 'NSFileModificationDate',
  protection: 'NSFileProtectionKey'
}

type AttributeKey = keyof typeof attributeLookup
export type Attributes = Record<AttributeKey, string | number>

export function attrs(path: string): Attributes {
  const { NSFileManager, NSString } = ObjC.classes
  const pError = Memory.alloc(Process.pointerSize).writePointer(NULL)
  const attr = NSFileManager.defaultManager()
    .attributesOfItemAtPath_error_(NSString.stringWithString_(path), pError)

  const err = pError.readPointer()
  if (!err.isNull())
    throw new Error(new ObjC.Object(err).localizedDescription())

  const result: Attributes = {} as Attributes
  for (const [jsKey, ocKey] of Object.entries(attributeLookup))
    result[jsKey as AttributeKey] = valueOf(attr.objectForKey_(ocKey))

  return result
}

import ObjC from 'frida-objc-bridge'

import { CFSTR } from '../lib/foundation.js'
import { valueOf } from '../lib/dict.js'

const CoreFoundation = Process.findModuleByName('CoreFoundation')
const Security = Process.findModuleByName('Security')
const Foundation = Process.findModuleByName('Foundation')

if (!(CoreFoundation && Security && Foundation)) {
  throw new Error('one or more required modules not loaded')
}

const constants = [
  'kSecReturnAttributes',
  'kSecReturnData',
  'kSecReturnRef',
  'kSecValueData',
  'kSecMatchLimit',
  'kSecMatchLimitAll',
  'kSecClass',
  'kSecClassKey',
  'kSecClassIdentity',
  'kSecClassCertificate',
  'kSecClassGenericPassword',
  'kSecClassInternetPassword',
  'kSecAttrService',
  'kSecAttrAccount',
  'kSecAttrAccessGroup',
  'kSecAttrLabel',
  'kSecAttrCreationDate',
  'kSecAttrAccessControl',
  'kSecAttrGeneric',
  'kSecAttrSynchronizable',
  'kSecAttrModificationDate',
  'kSecAttrServer',
  'kSecAttrDescription',
  'kSecAttrComment',
  'kSecAttrCreator',
  'kSecAttrType',
  'kSecAttrScriptCode',
  'kSecAttrAlias',
  'kSecAttrIsInvisible',
  'kSecAttrIsNegative',
  'kSecAttrHasCustomIcon',
  'kSecAttrAccessible',
  'kSecAttrAccessibleWhenUnlocked',
  'kSecAttrAccessibleAfterFirstUnlock',
  'kSecAttrAccessibleAlways',
  'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
  'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
  'kSecAttrAccessibleAlwaysThisDeviceOnly',

  'kSecUseAuthenticationUIFail',
  'kSecUseAuthenticationUI',
]

const lookup: { [val: string]: string } = {}
const C: { [key: string]: NativePointer } = {}
for (let symbol of constants) {
  const p = Security.findExportByName(symbol)
  if (!p) {
    console.error(`${symbol} not found`)
    continue
  }
  const val = p.readPointer()
  C[symbol] = val
  const literal = CFSTR(val)
  if (!literal) throw new Error(`Unable to resolve string constant ${symbol}`)
  lookup[literal] = symbol
}

const constantLookup = (val: string) => lookup[val]

const kSecClasses = [
  C.kSecClassKey,
  C.kSecClassIdentity,
  C.kSecClassCertificate,
  C.kSecClassGenericPassword,
  C.kSecClassInternetPassword
]

function readableAccount(val?: ObjC.Object) {
  if (val instanceof ObjC.Object && val.isKindOfClass_(ObjC.classes.NSData)) {
    const str = ObjC.classes.NSString.alloc().initWithData_encoding_(val, 4)
    if (str) return str.toString()
    return str
  }
  return `${val}`
}

function encodeData(val?: ObjC.Object) {
  if (val instanceof ObjC.Object && val.isKindOfClass_(ObjC.classes.NSData)) {
    return val.base64EncodedStringWithOptions_(0).toString()
  }
  return null
}

const SecItemCopyMatching = new NativeFunction(Security.findExportByName('SecItemCopyMatching')!, 'int', ['pointer', 'pointer'])
const SecItemDelete = new NativeFunction(Security.findExportByName('SecItemDelete')!, 'int', ['pointer'])

export function list(withfaceId = false): object[] {
  const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true)
  const result: object[] = []

  const query = ObjC.classes.NSMutableDictionary.alloc().init()
  query.setObject_forKey_(kCFBooleanTrue, C.kSecReturnAttributes)
  query.setObject_forKey_(kCFBooleanTrue, C.kSecReturnData)
  query.setObject_forKey_(kCFBooleanTrue, C.kSecReturnRef)
  query.setObject_forKey_(C.kSecMatchLimitAll, C.kSecMatchLimit)

  if (!withfaceId) {
    query.setObject_forKey_(C.kSecUseAuthenticationUIFail, C.kSecUseAuthenticationUI)
  }

  const KEY_MAPPING = {
    creation: C.kSecAttrCreationDate,
    modification: C.kSecAttrModificationDate,
    description: C.kSecAttrDescription,
    comment: C.kSecAttrComment,
    creator: C.kSecAttrCreator,
    type: C.kSecAttrType,
    scriptCode: C.kSecAttrScriptCode,
    alias: C.kSecAttrAlias,
    invisible: C.kSecAttrIsInvisible,
    negative: C.kSecAttrIsNegative,
    customIcon: C.kSecAttrHasCustomIcon,
    entitlementGroup: C.kSecAttrAccessGroup,
    generic: C.kSecAttrGeneric,
    service: C.kSecAttrService,
    // account: C.kSecAttrAccount,
    label: C.kSecAttrLabel,
    data: C.kSecValueData
  }

  for (const clazz of kSecClasses) {
    const className = CFSTR(clazz)
    query.setObject_forKey_(clazz, C.kSecClass)

    const p = Memory.alloc(Process.pointerSize)
    const status = SecItemCopyMatching(query, p)
    if (status)
      continue

    const arr = new ObjC.Object(p.readPointer())
    for (let i = 0, size = arr.count(); i < size; i++) {
      const item = arr.objectAtIndex_(i)
      const readable: { [key: string]: any } = {
        clazz: constantLookup(className!),
        // todo: bugfix
        // accessControl: dumpACL(item),
        accessibleAttribute: constantLookup(item.objectForKey_(C.kSecAttrAccessible))
      }

      for (const [key, attr] of Object.entries(KEY_MAPPING)) {
        readable[key] = valueOf(item.objectForKey_(attr))
      }

      readable['account'] = readableAccount(item.objectForKey_(C.kSecAttrAccount))
      readable['raw'] = encodeData(item.objectForKey_(C.kSecValueData))
      result.push(readable)
    }
  }

  return result
}

export function clear() {
  const query = ObjC.classes.NSMutableDictionary.alloc().init()
  for (const clazz of kSecClasses) {
    query.setObject_forKey_(clazz, C.kSecClass)
  }
  SecItemDelete(query)
  return true
}

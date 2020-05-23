import { valueOf } from '../lib/dict'

const { NSMutableDictionary } = ObjC.classes

function api(symbol: string, ret: string, args: string[]) {
  return new NativeFunction(Module.findExportByName('Security', symbol)!, ret, args)
}

const Security = {
  SecItemCopyMatching: api('SecItemCopyMatching', 'pointer', ['pointer', 'pointer']),
  SecItemDelete: api('SecItemDelete', 'pointer', ['pointer']),
  SecAccessControlGetConstraints: api('SecAccessControlGetConstraints', 'pointer', ['pointer']),
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

const lookup: {[val: string]: string } = {}
const C: { [key: string]: NativePointer } = {}
for (let symbol of constants) {
  const p = Module.findExportByName('Security', symbol)
  if (!p) {
    console.error(`${symbol} not found`)
    continue
  }
  const val = p.readPointer()
  C[symbol] = val
  lookup[val.toString()] = symbol
}

Module.ensureInitialized('Foundation')
Module.ensureInitialized('CoreFoundation')

const constantLookup = (val: NativePointer) => lookup[val.toString()]
const CFRelease = new NativeFunction(Module.findExportByName('CoreFoundation', 'CFRelease')!, 'void', ['pointer'])

const kSecClasses = [
  C.kSecClassKey,
  C.kSecClassIdentity,
  C.kSecClassCertificate,
  C.kSecClassGenericPassword,
  C.kSecClassInternetPassword
]

function dumpACL(entry: ObjC.Object): string {
  if (!entry.containsKey_(C.kSecAttrAccessControl))
    return ''

  const constraints = Security.SecAccessControlGetConstraints(
    entry.objectForKey_(C.kSecAttrAccessControl)) as NativePointer

  if (constraints.isNull())
    return ''

  const { NSDictionary, NSData } = ObjC.classes
  const CFGetTypeID = new NativeFunction(Module.findExportByName('CoreFoundation', 'CFGetTypeID')!, 'pointer', ['pointer'])
  const CFBooleanGetTypeID = new NativeFunction(Module.findExportByName('CoreFoundation', 'CFBooleanGetTypeID')!, 'pointer', [])

  class Visitor {
    constructor(public node: ObjC.Object) {}

    visit(node: ObjC.Object): string {
      if (node.isKindOfClass_(NSDictionary))
        return [...this.expand(node)].join(';')
      if ((CFGetTypeID(node) as NativePointer).equals(CFBooleanGetTypeID() as NativePointer))
      // if (node.isKindOfClass_(NSNumber))
        return node.boolValue().toString()
      if (node.isKindOfClass_(NSData))
        return '<>'
      return node.toString()
    }

    *expand(node: ObjC.Object) {      
      const enumerator = node.keyEnumerator()
      let key
      while ((key = enumerator.nextObject())) {
        let value = node.objectForKey_(key)
        yield `${key}(${this.visit(value)})`
      }
    }
    
    toString() {
      return 'ak;' + this.visit(this.node)
    }
  }

  // SecAccessControlCopyDescription
  const accessControls = new ObjC.Object(constraints)
  return new Visitor(accessControls).toString()
}

/* eslint no-unused-vars: 0 */
// const SecAccessControlCreateFlags = {
const
  kSecAccessControlUserPresence = new UInt64(1 << 0),
  kSecAccessControlBiometryAny = new UInt64(1 << 1),
  kSecAccessControlBiometryCurrentSet = new UInt64(1 << 3),
  kSecAccessControlDevicePasscode = new UInt64(1 << 4),
  kSecAccessControlWatch = new UInt64(1 << 5),
  kSecAccessControlOr = new UInt64(1 << 14),
  kSecAccessControlAnd = new UInt64(1 << 15),
  kSecAccessControlPrivateKeyUsage = new UInt64(1 << 30),
  kSecAccessControlApplicationPassword = new UInt64('2147483648')
// }

export function list(withfaceId = false): object[] {
  const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true)
  const result: object[] = []

  const query = NSMutableDictionary.alloc().init()
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
    account: C.kSecAttrAccount,
    label: C.kSecAttrLabel,
    data: C.kSecValueData
  }

  for (const clazz of kSecClasses) {
    query.setObject_forKey_(clazz, C.kSecClass)

    const p = Memory.alloc(Process.pointerSize)
    const status = Security.SecItemCopyMatching(query, p) as NativePointer
    if (!status.isNull())
      continue

    const arr = new ObjC.Object(p.readPointer())
    for (let i = 0, size = arr.count(); i < size; i++) {
      const item = arr.objectAtIndex_(i)
      const readable: { [key: string]: any } = {
        clazz: constantLookup(clazz),
        accessControl: dumpACL(item),
        accessibleAttribute: constantLookup(item.objectForKey_(C.kSecAttrAccessible))
      }

      for (const [key, attr] of Object.entries(KEY_MAPPING)) {
        readable[key] = valueOf(item.objectForKey_(attr))
      }

      result.push(readable)
    }
  }

  query.release()
  return result
}

export function clear() {
  const query = NSMutableDictionary.alloc().init()
  for (const clazz of kSecClasses) {
    query.setObject_forKey_(clazz, C.kSecClass)
  }
  Security.SecItemDelete(query)
  return true
}

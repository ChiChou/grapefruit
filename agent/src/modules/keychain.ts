import { valueOf } from '../bridge/dictionary.js'
import { expose } from '../registry.js'

for (const mod of ['Foundation', 'CoreFoundation', 'Security']) {
  Module.ensureInitialized(mod)
}

const CFStringGetCStringPtr = new NativeFunction(
  Module.findExportByName('CoreFoundation', 'CFStringGetCStringPtr')!, 'pointer', ['pointer', 'int']);
const CFStringGetLength = new NativeFunction(
  Module.findExportByName('CoreFoundation', 'CFStringGetLength')!, 'int', ['pointer']);

function CFSTR(p: NativePointer) {
  const kCFStringEncodingUTF8 = 0x08000100
  const str = CFStringGetCStringPtr(p, kCFStringEncodingUTF8) as NativePointer
  return str.readUtf8String(CFStringGetLength(p) as number)
}

const SecItemCopyMatching = new NativeFunction(Module.findExportByName('Security', 'SecItemCopyMatching')!, 'int', ['pointer', 'pointer'])
const SecItemAdd = new NativeFunction(Module.findExportByName('Security', 'SecItemAdd')!, 'int', ['pointer', 'pointer'])
const SecItemUpdate = new NativeFunction(Module.findExportByName('Security', 'SecItemUpdate')!, 'int', ['pointer', 'pointer'])
const SecItemDelete = new NativeFunction(Module.findExportByName('Security', 'SecItemDelete')!, 'int', ['pointer'])
const SecAccessControlCreateWithFlags = new NativeFunction(Module.findExportByName('Security', 'SecAccessControlCreateWithFlags')!, 'pointer', ['pointer', 'pointer', 'int', 'pointer'])

// todo: convert code
const AttributeKeysValues = [
  'kSecAttrService',
  'kSecAttrAccount',
  'kSecAttrGeneric',
  'kSecAttrSecurityDomain',
  'kSecAttrServer',
  'kSecAttrProtocol',
  'kSecAttrAuthenticationType',
  'kSecAttrPort',
  'kSecAttrPath'
] as const

type AttributeKeys = typeof AttributeKeysValues[number]

namespace KeyChain {
  // https://developer.apple.com/documentation/security/keychain_services/keychain_items/item_attribute_keys_and_values#2882540

  interface AttributeKeys {
    kSecAttrService: NativePointer,
    kSecAttrAccount: NativePointer,
    kSecAttrGeneric: NativePointer,
    kSecAttrSecurityDomain: NativePointer,
    kSecAttrServer: NativePointer,
    kSecAttrProtocol: NativePointer,
    kSecAttrAuthenticationType: NativePointer,
    kSecAttrPort: NativePointer,
    kSecAttrPath: NativePointer,
  }

  interface ItemResultKeys {
    kSecReturnData: NativePointer,
    kSecReturnAttributes: NativePointer,
    kSecReturnRef: NativePointer,
    kSecReturnPersistentRef: NativePointer,
  }

  interface ItemValueTypeKeys {
    kSecValueData: NativePointer,
    kSecValueRef: NativePointer,
    kSecValuePersistentRef: NativePointer,
  }

  interface ItemSearchMatchingKeys {
    kSecMatchPolicy: NativePointer,
    kSecMatchItemList: NativePointer,
    kSecMatchSearchList: NativePointer,
    kSecMatchIssuers: NativePointer,
    kSecMatchEmailAddressIfPresent: NativePointer,
    kSecMatchSubjectContains: NativePointer,
    kSecMatchSubjectStartsWith: NativePointer,
    kSecMatchSubjectEndsWith: NativePointer,
    kSecMatchSubjectWholeString: NativePointer,
    kSecMatchCaseInsensitive: NativePointer,
    kSecMatchDiacriticInsensitive: NativePointer,
    kSecMatchWidthInsensitive: NativePointer,
    kSecMatchTrustedOnly: NativePointer,
    kSecMatchValidOnDate: NativePointer,
    kSecMatchLimit: NativePointer,
  }

  interface MatchLimitKeys {
    kSecMatchLimitOne: NativePointer,
    kSecMatchLimitAll: NativePointer,
  }

  interface AddictionalItemSearchKeys {
    kSecUseItemList: NativePointer,
    kSecUseKeychain: NativePointer,
    kSecUseOperationPrompt: NativePointer, // deprecated
    kSecUseNoAuthenticationUI: NativePointer, // deprecated
    kSecUseAuthenticationContext: NativePointer,
    kSecUseAuthenticationUI: NativePointer,
  }

  interface UIAuthenticationValues {
    kSecUseAuthenticationUIAllow: NativePointer, // deperecated
    kSecUseAuthenticationUIFail: NativePointer, // deprecated
    kSecUseAuthenticationUISkip: NativePointer,
  }
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
  const p = Module.findExportByName('Security', symbol)
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

const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true)

export function list(withfaceId = false): object[] {
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
    if (status !== 0)
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

expose('keychain', { list, clear })

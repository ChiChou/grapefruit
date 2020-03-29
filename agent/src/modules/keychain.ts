import { valueOf } from '../lib/dict'

const { NSMutableDictionary } = ObjC.classes

const SecItemCopyMatching = new NativeFunction(Module.findExportByName('Security', 'SecItemCopyMatching')!, 'pointer', ['pointer', 'pointer'])
const SecItemDelete = new NativeFunction(Module.findExportByName('Security', 'SecItemDelete')!, 'pointer', ['pointer'])
const SecAccessControlGetConstraints = new NativeFunction(Module.findExportByName('Security', 'SecAccessControlGetConstraints')!, 'pointer', ['pointer'])

const kCFBooleanTrue = ObjC.classes.__NSCFBoolean.numberWithBool_(true)

/* eslint no-unused-vars: 0 */
const kSecReturnAttributes = 'r_Attributes',
  kSecReturnData = 'r_Data',
  kSecReturnRef = 'r_Ref',
  kSecMatchLimit = 'm_Limit',
  kSecMatchLimitAll = 'm_LimitAll',
  kSecClass = 'class',
  kSecClassKey = 'keys',
  kSecClassIdentity = 'idnt',
  kSecClassCertificate = 'cert',
  kSecClassGenericPassword = 'genp',
  kSecClassInternetPassword = 'inet',
  kSecAttrService = 'svce',
  kSecAttrAccount = 'acct',
  kSecAttrAccessGroup = 'agrp',
  kSecAttrLabel = 'labl',
  kSecAttrCreationDate = 'cdat',
  kSecAttrAccessControl = 'accc',
  kSecAttrGeneric = 'gena',
  kSecAttrSynchronizable = 'sync',
  kSecAttrModificationDate = 'mdat',
  kSecAttrServer = 'srvr',
  kSecAttrDescription = 'desc',
  kSecAttrComment = 'icmt',
  kSecAttrCreator = 'crtr',
  kSecAttrType = 'type',
  kSecAttrScriptCode = 'scrp',
  kSecAttrAlias = 'alis',
  kSecAttrIsInvisible = 'invi',
  kSecAttrIsNegative = 'nega',
  kSecAttrHasCustomIcon = 'cusi',
  kSecProtectedDataItemAttr = 'prot',
  kSecAttrAccessible = 'pdmn',
  kSecAttrAccessibleWhenUnlocked = 'ak',
  kSecAttrAccessibleAfterFirstUnlock = 'ck',
  kSecAttrAccessibleAlways = 'dk',
  kSecAttrAccessibleWhenUnlockedThisDeviceOnly = 'aku',
  kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly = 'cku',
  kSecAttrAccessibleAlwaysThisDeviceOnly = 'dku'

const kSecConstantReverse: {[key: string]: string} = {
  r_Attributes: 'kSecReturnAttributes',
  r_Data: 'kSecReturnData',
  r_Ref: 'kSecReturnRef',
  m_Limit: 'kSecMatchLimit',
  m_LimitAll: 'kSecMatchLimitAll',
  class: 'kSecClass',
  keys: 'kSecClassKey',
  idnt: 'kSecClassIdentity',
  cert: 'kSecClassCertificate',
  genp: 'kSecClassGenericPassword',
  inet: 'kSecClassInternetPassword',
  svce: 'kSecAttrService',
  acct: 'kSecAttrAccount',
  agrp: 'kSecAttrAccessGroup',
  labl: 'kSecAttrLabel',
  srvr: 'kSecAttrServer',
  cdat: 'kSecAttrCreationDate',
  accc: 'kSecAttrAccessControl',
  gena: 'kSecAttrGeneric',
  sync: 'kSecAttrSynchronizable',
  mdat: 'kSecAttrModificationDate',
  desc: 'kSecAttrDescription',
  icmt: 'kSecAttrComment',
  crtr: 'kSecAttrCreator',
  type: 'kSecAttrType',
  scrp: 'kSecAttrScriptCode',
  alis: 'kSecAttrAlias',
  invi: 'kSecAttrIsInvisible',
  nega: 'kSecAttrIsNegative',
  cusi: 'kSecAttrHasCustomIcon',
  prot: 'kSecProtectedDataItemAttr',
  pdmn: 'kSecAttrAccessible',
  ak: 'kSecAttrAccessibleWhenUnlocked',
  ck: 'kSecAttrAccessibleAfterFirstUnlock',
  dk: 'kSecAttrAccessibleAlways',
  aku: 'kSecAttrAccessibleWhenUnlockedThisDeviceOnly',
  cku: 'kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly',
  dku: 'kSecAttrAccessibleAlwaysThisDeviceOnly'
}

const constantLookup = (v: string) => kSecConstantReverse[v] || v

const kSecClasses = [
  kSecClassKey,
  kSecClassIdentity,
  kSecClassCertificate,
  kSecClassGenericPassword,
  kSecClassInternetPassword
]

function decodeAcl(entry: ObjC.Object) {
  if (!entry.containsKey_(kSecAttrAccessControl))
    return []

  const constraints = SecAccessControlGetConstraints(entry.objectForKey_(kSecAttrAccessControl)) as NativePointer
  if (constraints.isNull())
    return []

  const accessControls = new ObjC.Object(constraints)
  function *od(dict: ObjC.Object) {
    const enumerator = dict.keyEnumerator()
    let key
    while ((key = enumerator.nextObject())) {
      const item = dict.objectForKey_(key)
      const str = key.toString()
      if (str === 'cpo') {
        yield 'kSecAccessControlUserPresence'
      } else if (str === 'cup') {
        yield 'kSecAccessControlDevicePasscode'
      } else if (str === 'pkofn') {
        yield item.count() === 1 ? 'Or' : 'And'
      } else if (str === 'cbio') {
        yield item.count() === 1 ? 'kSecAccessControlTouchIDAny' : 'kSecAccessControlTouchIDCurrentSet'
      }
    }
  }

  function *flags(acl: ObjC.Object) {
    const enumerator = acl.keyEnumerator()
    let key
    while ((key = enumerator.nextObject())) {
      const item = acl.objectForKey_(key)
      const str = key.toString()
      if (str === 'dacl') {

      } else if (str === 'osgn') {
        yield 'PrivateKeyUsage'
      } else if (str === 'od') {
        yield *od(item)
      } else if (str === 'prp') {
        yield 'ApplicationPassword'
      }
    }
  }

  return [...flags(accessControls)]
}

export function list() {
  const result = []

  const query = NSMutableDictionary.alloc().init()
  query.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes)
  query.setObject_forKey_(kCFBooleanTrue, kSecReturnData)
  query.setObject_forKey_(kCFBooleanTrue, kSecReturnRef)
  query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit)

  const KEY_MAPPING = {
    creation: kSecAttrCreationDate,
    modification: kSecAttrModificationDate,
    description: kSecAttrDescription,
    comment: kSecAttrComment,
    creator: kSecAttrCreator,
    type: kSecAttrType,
    scriptCode: kSecAttrScriptCode,
    alias: kSecAttrAlias,
    invisible: kSecAttrIsInvisible,
    negative: kSecAttrIsNegative,
    customIcon: kSecAttrHasCustomIcon,
    protected: kSecProtectedDataItemAttr,
    entitlementGroup: kSecAttrAccessGroup,
    generic: kSecAttrGeneric,
    service: kSecAttrService,
    account: kSecAttrAccount,
    label: kSecAttrLabel,
    data: 'v_Data'
  }

  for (const clazz of kSecClasses) {
    query.setObject_forKey_(clazz, kSecClass)

    const p = Memory.alloc(Process.pointerSize)
    const status = SecItemCopyMatching(query, p) as NativePointer
    if (!status.isNull())
      continue

    const arr = new ObjC.Object(p.readPointer())
    for (let i = 0, size = arr.count(); i < size; i++) {
      const item = arr.objectAtIndex_(i)
      const readable: { [key: string]: any } = {
        clazz: constantLookup(clazz),
        accessControl: decodeAcl(item),
        accessibleAttribute: constantLookup(item.objectForKey_(kSecAttrAccessible))
      }

      for (const [key, attr] of Object.entries(KEY_MAPPING)) {
        readable[key] = valueOf(item.objectForKey_(attr))
      }

      result.push(readable)
    }
  }

  return result
}

export function clear() {
  const query = NSMutableDictionary.alloc().init()
  for (const clazz of kSecClasses) {
    query.setObject_forKey_(clazz, kSecClass)
  }
  SecItemDelete(query)
  return true
}

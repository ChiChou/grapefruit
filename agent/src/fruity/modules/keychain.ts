import ObjC from "frida-objc-bridge";
import { toJS } from "@/fruity/bridge/object.js";
import cf from "@/fruity/native/corefoundation.js";
import getSecurityApi from "@/fruity/native/security.js";
import { describe as acl } from "./keychain-acl.js";

function kSec(suffix: string) {
  return Process.getModuleByName("Security")
    .getExportByName(`kSec${suffix}`)
    .readPointer();
}

const kSecClasses = {
  id: kSec("ClassIdentity"),
  cert: kSec("ClassCertificate"),
  key: kSec("ClassKey"),
  generic: kSec("ClassGenericPassword"),
  internet: kSec("ClassInternetPassword"),
};

function encodeData(val?: ObjC.Object) {
  if (val instanceof ObjC.Object && val.isKindOfClass_(ObjC.classes.NSData)) {
    return val.base64EncodedStringWithOptions_(0).toString();
  }
  return undefined;
}

function readableAccount(val?: ObjC.Object) {
  if (!val) return undefined;
  if (val instanceof ObjC.Object && val.isKindOfClass_(ObjC.classes.NSData)) {
    const str = ObjC.classes.NSString!.alloc().initWithData_encoding_(val, 4);
    if (str) {
      const value = str.toString();
      str.release();
      return value;
    }
    return undefined;
  }
  return `${val}`;
}

export interface KeyChainItem {
  clazz?: string;
  creation?: Date;
  modification?: Date;
  description?: string;
  comment?: string;
  creator?: string;
  type?: string;
  scriptCode?: number;
  alias?: boolean;
  invisible?: boolean;
  negative?: boolean;
  customIcon?: boolean;
  entitlementGroup?: string;
  generic?: string;
  service?: string;
  account?: string;
  label?: string;
  data?: string;
  raw?: string;
  persistentRef?: string;
  acl?: string;
  prot?: string;
}

const cf2str = (cf: NativePointer) => new ObjC.Object(cf).toString();
const enumLookup = (prefix: string) =>
  Object.fromEntries(
    Process.getModuleByName("Security")
      .enumerateExports()
      .filter((e) => e.name.startsWith(prefix))
      .map((e) => [cf2str(e.address.readPointer()), e.name]),
  );

export function remove(persistentRef: string) {
  const ref = ObjC.classes.NSData!.alloc().initWithBase64EncodedString_options_(
    persistentRef,
    0,
  );
  if (!ref) throw new Error("Invalid persistent keychain reference");

  let status: number;
  try {
    const query = ObjC.classes.NSMutableDictionary!.dictionary();
    query.setObject_forKey_(ref, kSec("ValuePersistentRef"));
    status = getSecurityApi().SecItemDelete(query);
  } finally {
    ref.release();
  }

  const errSecItemNotFound = -25300;
  if (status === errSecItemNotFound) throw new Error("errSecItemNotFound");
  if (status !== 0)
    throw new Error(`SecItemDelete returned non zero result ${status}`);
}

export function list(withBiometricId = false): KeyChainItem[] {
  const { SecItemCopyMatching, SecAccessControlGetProtection } =
    getSecurityApi();
  const { CFRelease } = cf();

  const kSecAttrAccessibleLookup = enumLookup("kSecAttrAccessible");

  const result: KeyChainItem[] = [];
  const kCFBooleanTrue = ObjC.classes.__NSCFBoolean!.numberWithBool_(true);
  const query = ObjC.classes.NSMutableDictionary!.dictionary();
  query.setObject_forKey_(kCFBooleanTrue, kSec("ReturnAttributes"));
  query.setObject_forKey_(kCFBooleanTrue, kSec("ReturnData"));
  query.setObject_forKey_(kCFBooleanTrue, kSec("ReturnPersistentRef"));
  query.setObject_forKey_(kSec("MatchLimitAll"), kSec("MatchLimit"));

  if (!withBiometricId) {
    query.setObject_forKey_(
      kSec("UseAuthenticationUISkip"),
      kSec("UseAuthenticationUI"),
    );
  }

  const KEY_MAPPING = {
    creation: kSec("AttrCreationDate"),
    modification: kSec("AttrModificationDate"),
    description: kSec("AttrDescription"),
    comment: kSec("AttrComment"),
    creator: kSec("AttrCreator"),
    type: kSec("AttrType"),
    scriptCode: kSec("AttrScriptCode"),
    alias: kSec("AttrAlias"),
    invisible: kSec("AttrIsInvisible"),
    negative: kSec("AttrIsNegative"),
    customIcon: kSec("AttrHasCustomIcon"),
    entitlementGroup: kSec("AttrAccessGroup"),
    generic: kSec("AttrGeneric"),
    service: kSec("AttrService"),
    account: kSec("AttrAccount"),
    label: kSec("AttrLabel"),
  };

  for (const [className, clazz] of Object.entries(kSecClasses)) {
    query.setObject_forKey_(clazz, kSec("Class"));

    const p = Memory.alloc(Process.pointerSize).writePointer(NULL);
    const status = SecItemCopyMatching(query, p);
    if (status !== 0) continue;

    const found = p.readPointer();
    if (found.isNull()) continue;

    try {
      const arr = new ObjC.Object(found);
      for (let i = 0, size = arr.count(); i < size; i++) {
        const item = arr.objectAtIndex_(i);
        const access = item.objectForKey_(kSec("AttrAccessControl"));
        const readable: KeyChainItem = {
          clazz: className,
          acl: acl(access),
        };

        let prot = item.objectForKey_(kSec("AttrAccessible"));
        if (!prot && access) {
          const value = SecAccessControlGetProtection(access);
          if (!value.isNull()) prot = new ObjC.Object(value);
        }
        if (prot) {
          const value = prot.toString();
          readable.prot = kSecAttrAccessibleLookup[value] ?? value;
        }

        for (const [key, attr] of Object.entries(KEY_MAPPING) as Array<
          [keyof KeyChainItem, NativePointer]
        >) {
          const v = item.objectForKey_(attr);
          if (v) {
            (readable as Partial<Record<keyof KeyChainItem, unknown>>)[key] =
              v.isKindOfClass_(ObjC.classes.NSData) ? v.toString() : toJS(v);
          }
        }

        const valueData = item.objectForKey_(kSec("ValueData"));
        if (valueData) {
          readable.data = valueData.toString();
          readable.raw = encodeData(valueData);
        }
        readable.account = readableAccount(
          item.objectForKey_(kSec("AttrAccount")),
        );
        readable.persistentRef = encodeData(
          item.objectForKey_(kSec("ValuePersistentRef")),
        );
        result.push(readable);
      }
    } finally {
      CFRelease(found);
    }
  }

  return result;
}

import ObjC from "frida-objc-bridge";
import { valueOf } from "../bridge/dictionary.js";
import getSecurityApi from "../native/security.js";

function kSec(suffix: string) {
  return Process.getModuleByName("Security")
    .getExportByName(`kSec${suffix}`)
    .readPointer();
}

const kCFBooleanTrue = ObjC.classes.__NSCFBoolean!.numberWithBool_(true);

const kSecClasses = {
  id: kSec("ClassIdentity"),
  cert: kSec("ClassCertificate"),
  generic: kSec("ClassGenericPassword"),
  internet: kSec("ClassInternetPassword"),
};

function encodeData(val?: ObjC.Object) {
  if (val instanceof ObjC.Object && val.isKindOfClass_(ObjC.classes.NSData)) {
    return val.base64EncodedStringWithOptions_(0).toString();
  }
  return null;
}

function readableAccount(val?: ObjC.Object) {
  if (val instanceof ObjC.Object && val.isKindOfClass_(ObjC.classes.NSData)) {
    const str = ObjC.classes.NSString!.alloc().initWithData_encoding_(val, 4);
    if (str) return str.toString();
    return str;
  }
  return `${val}`;
}

interface KeyChainItem {
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

function dumpACL(item: ObjC.Object) {
  const kAKSKeyOpAttest = "oa";
  const kAKSKeyOpDecrypt = "od";
  const kAKSKeyOpSign = "osgn";
  const kACMKeyAclConstraintPolicy = "cpol";
  const kACMPolicyDeviceOwnerAuthentication = "DeviceOwnerAuthentication";
  const kACMKeyAclConstraintUserPasscode = "cup";
  const kACMKeyAclConstraintWatch = "cwtch";
  const kACMKeyAclConstraintBio = "cbio";
  const kAKSKeyOpDefaultAcl = "dacl";
  const kACMKeyAclParamKofN = "pkofn";

  const {
    SecAccessControlGetRequirePassword,
    SecAccessControlGetConstraints,
    SecAccessControlGetConstraint,
  } = getSecurityApi();

  const access = item.objectForKey_(kSec("AttrAccessControl"));
  if (!access) return;

  function* gen() {
    if (SecAccessControlGetRequirePassword(access))
      yield "kSecAccessControlApplicationPassword";

    const constriants = SecAccessControlGetConstraints(access);
    if (constriants.isNull()) return;

    const dict = new ObjC.Object(constriants);

    const isPrivateKey = dict.objectForKey_(kAKSKeyOpAttest);
    if (isPrivateKey) {
      yield "kSecAccessControlPrivateKeyUsage";
    }

    let opDict = dict.objectForKey_(kAKSKeyOpDecrypt);
    if (isPrivateKey) {
      opDict = dict.objectForKey_(kAKSKeyOpSign);
    }

    if (!opDict || !opDict.isKindOfClass_(ObjC.classes.NSDictionary)) {
      opDict = dict; // top-level dictionary
    }

    const policy = opDict.objectForKey_(kACMKeyAclConstraintPolicy);
    if (policy) {
      if (policy.isEqualToString_(kACMPolicyDeviceOwnerAuthentication)) {
        yield "kSecAccessControlUserPresence";
      } else {
        yield "Policy: " + policy.toString();
      }
    }

    if (opDict.objectForKey_(kACMKeyAclConstraintUserPasscode)) {
      yield "kSecAccessControlDevicePasscode";
    }

    const cbio = opDict.objectForKey_(kACMKeyAclConstraintBio);
    if (cbio) {
      yield cbio.count().intValue() > 1
        ? "kSecAccessControlBiometryCurrentSet"
        : "kSecAccessControlBiometryAny";
    }

    if (opDict.objectForKey_(kACMKeyAclConstraintWatch)) {
      yield "kSecAccessControlCompanion";
    }

    const pkofn = opDict.objectForKey_(kACMKeyAclParamKofN);
    if (pkofn) {
      yield pkofn.value() === 1
        ? "kSecAccessControlOr"
        : "kSecAccessControlAnd";
    }
  }

  const list = [...gen()];
  if (
    !list.length &&
    SecAccessControlGetConstraint(
      access,
      ObjC.classes.NSString!.stringWithString_(kAKSKeyOpDefaultAcl),
    )
  ) {
    return "default";
  }

  return list.join(" | ");
}

export function list(withfaceId = false): KeyChainItem[] {
  const { SecItemCopyMatching, SecAccessControlGetProtection } =
    getSecurityApi();

  const kSecAttrAccessibleLookup = enumLookup("kSecAttrAccessible");

  const result: KeyChainItem[] = [];
  const query = ObjC.classes.NSMutableDictionary!.alloc().init();
  query.setObject_forKey_(kCFBooleanTrue, kSec("ReturnAttributes"));
  query.setObject_forKey_(kCFBooleanTrue, kSec("ReturnData"));
  query.setObject_forKey_(kCFBooleanTrue, kSec("ReturnRef"));
  query.setObject_forKey_(kSec("MatchLimitAll"), kSec("MatchLimit"));

  if (!withfaceId) {
    query.setObject_forKey_(
      kSec("UseAuthenticationUIFail"),
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
    data: kSec("ValueData"),
  };

  for (const [className, clazz] of Object.entries(kSecClasses)) {
    query.setObject_forKey_(clazz, kSec("Class"));

    const p = Memory.alloc(Process.pointerSize);
    const status = SecItemCopyMatching(query, p);
    if (status !== 0) continue;

    const arr = new ObjC.Object(p.readPointer());
    for (let i = 0, size = arr.count(); i < size; i++) {
      const item = arr.objectAtIndex_(i);
      const readable: KeyChainItem = {
        clazz: className,
        acl: dumpACL(item),
      };

      const access = item.objectForKey_(kSec("AttrAccessControl"));
      const prot = SecAccessControlGetProtection(access);
      readable.prot = kSecAttrAccessibleLookup[cf2str(prot)];

      for (const [key, attr] of Object.entries(KEY_MAPPING)) {
        const v = item.objectForKey_(attr);
        if (v) readable[key as keyof KeyChainItem] = valueOf(v);
      }

      readable.account = readableAccount(
        item.objectForKey_(kSec("AttrAccount")),
      );
      readable.raw = encodeData(item.objectForKey_(kSec("ValueData")));
      result.push(readable);
    }
  }

  return result;
}

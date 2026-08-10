import ObjC from "frida-objc-bridge";
import getSecurityApi from "@/fruity/native/security.js";

export function describe(access?: ObjC.Object) {
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

  if (!access) return;
  const ref = access;

  const {
    SecAccessControlGetRequirePassword,
    SecAccessControlGetConstraints,
    SecAccessControlGetConstraint,
  } = getSecurityApi();

  function* gen() {
    if (SecAccessControlGetRequirePassword(ref))
      yield "kSecAccessControlApplicationPassword";

    const constraints = SecAccessControlGetConstraints(ref);
    if (constraints.isNull()) return;

    const dict = new ObjC.Object(constraints);
    const isPrivateKey = dict.objectForKey_(kAKSKeyOpAttest);
    if (isPrivateKey) yield "kSecAccessControlPrivateKeyUsage";

    let opDict = dict.objectForKey_(kAKSKeyOpDecrypt);
    if (isPrivateKey) opDict = dict.objectForKey_(kAKSKeyOpSign);
    if (!opDict || !opDict.isKindOfClass_(ObjC.classes.NSDictionary)) {
      opDict = dict;
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
      yield Number(cbio.count()) > 1
        ? "kSecAccessControlBiometryCurrentSet"
        : "kSecAccessControlBiometryAny";
    }

    if (opDict.objectForKey_(kACMKeyAclConstraintWatch)) {
      yield "kSecAccessControlCompanion";
    }

    const pkofn = opDict.objectForKey_(kACMKeyAclParamKofN);
    if (pkofn) {
      yield pkofn.intValue() === 1
        ? "kSecAccessControlOr"
        : "kSecAccessControlAnd";
    }
  }

  const list = [...gen()];
  const fallback = SecAccessControlGetConstraint(
    ref,
    ObjC.classes.NSString!.stringWithString_(kAKSKeyOpDefaultAcl),
  );
  if (!list.length && !fallback.isNull()) return "default";
  return list.join(" | ");
}

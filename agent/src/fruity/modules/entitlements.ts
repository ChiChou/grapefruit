import ObjC from "frida-objc-bridge";

import cf from "@/fruity/native/corefoundation.js";
import security from "@/fruity/native/security.js";
import { dump } from "@/fruity/lib/plist.js";

const kSecCSDefaultFlags = 0;
// const kSecCSInternalInformation = 1 << 0;
const kSecCSSigningInformation = 1 << 1;
const kSecCSRequirementInformation = 1 << 2;
// const kSecCSDynamicInformation = 1 << 3;
// const kSecCSContentInformation = 1 << 4;

export interface Entitlements {
  [key: string]: string | boolean | number | string[];
}

function dictionary(url: ObjC.Object): NativePointer {
  const {
    SecStaticCodeCreateWithPath,
    SecCodeCopySigningInformation,
    kSecCodeInfoEntitlementsDict,
  } = security();
  const { CFRetain, CFRelease } = cf();

  const pCodeRef = Memory.alloc(Process.pointerSize);
  const pSignInfo = Memory.alloc(Process.pointerSize);

  let rc = 0;

  rc = SecStaticCodeCreateWithPath(url, kSecCSDefaultFlags, pCodeRef);
  if (rc !== 0)
    throw new Error(
      `SecStaticCodeCreateWithPath failed with error code: ${rc}`,
    );

  const codeRef = pCodeRef.readPointer();
  rc = SecCodeCopySigningInformation(
    codeRef,
    kSecCSSigningInformation | kSecCSRequirementInformation,
    pSignInfo,
  );

  if (rc !== 0)
    throw new Error(
      `SecCodeCopySigningInformation failed with error code: ${rc}`,
    );

  const signInfo = pSignInfo.readPointer();
  const dict = new ObjC.Object(signInfo).objectForKey_(
    kSecCodeInfoEntitlementsDict,
  );

  try {
    return CFRetain(dict);
  } finally {
    CFRelease(signInfo);
    CFRelease(codeRef);
  }
}

function fromPath(path?: string) {
  const url = path
    ? ObjC.classes.NSURL.fileURLWithPath_(path)
    : ObjC.classes.NSBundle.mainBundle().bundleURL();
  if (!url) throw new Error(`invalid file url ${path}`);
  return dictionary(url);
}

export function plist(path?: string) {
  if (!ObjC.available) throw new Error("unsupported platform");

  const dict = fromPath(path);
  try {
    return dump(new ObjC.Object(dict));
  } finally {
    cf().CFRelease(dict);
  }
}

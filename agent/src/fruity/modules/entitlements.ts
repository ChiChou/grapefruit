import ObjC from "frida-objc-bridge";

import cf from "@/fruity/native/corefoundation.js";
import { NSData } from "@/fruity/typings.js";
import { dump, toJSON, toXML } from "@/fruity/lib/plist.js";

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
  ObjC.classes.NSBundle.bundleWithPath_(
    "/System/Library/Frameworks/Security.framework",
  ).load();

  const Security = Process.getModuleByName("Security");

  const SecStaticCodeCreateWithPath = new NativeFunction(
    Security.findExportByName("SecStaticCodeCreateWithPath")!,
    "int",
    ["pointer", "uint32", "pointer"],
  );

  const kSecCodeInfoEntitlementsDict = Security.findExportByName(
    "kSecCodeInfoEntitlementsDict",
  )!.readPointer();

  const SecCodeCopySigningInformation = new NativeFunction(
    Security.findExportByName("SecCodeCopySigningInformation")!,
    "int",
    ["pointer", "uint32", "pointer"],
  );

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
  const dict = fromPath(path);
  try {
    return dump(new ObjC.Object(dict));
  } finally {
    cf().CFRelease(dict);
  }
}

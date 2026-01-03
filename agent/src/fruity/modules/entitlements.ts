import ObjC from "frida-objc-bridge";

import { NSData } from "../typings.js";

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

const CoreFoundation = Process.getModuleByName("CoreFoundation");
const CFRelease = new NativeFunction(
  CoreFoundation.findExportByName("CFRelease")!,
  "void",
  ["pointer"],
);

const CFRetain = new NativeFunction(
  CoreFoundation.findExportByName("CFRetain")!,
  "pointer",
  ["pointer"],
);

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

function dataToString(data: NSData): string {
  const NSUTF8StringEncoding = 4;
  const nsstr = ObjC.classes.NSString.alloc().initWithData_encoding_(
    data,
    NSUTF8StringEncoding,
  );
  return nsstr.toString();
}

export function json(path?: string): string {
  const dict = fromPath(path);
  const data =
    ObjC.classes.NSJSONSerialization.dataWithJSONObject_options_error_(
      dict,
      0,
      NULL,
    );
  CFRelease(dict);
  return dataToString(data);
}

export function xml(path?: string): string {
  const NSPropertyListXMLFormat_v1_0 = 100;
  const dict = fromPath(path);
  const data =
    ObjC.classes.NSPropertyListSerialization.dataWithPropertyList_format_options_error_(
      dict,
      NSPropertyListXMLFormat_v1_0,
      0,
      NULL,
    );

  CFRelease(dict);
  return dataToString(data);
}

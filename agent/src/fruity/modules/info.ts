import ObjC from "frida-objc-bridge";
import type {
  NSDictionary,
  NSObject,
  StringLike,
  NSArray,
  NSData,
} from "../typings.js";

import { toJsArray, toJS } from "../bridge/object.js";

export interface URLScheme {
  name: string;
  schemes: string[];
  role: string;
}

export interface BasicInfo {
  tmp: string;
  home: string;
  id: string;
  label: string;
  path: string;
  main: string;
  version: string;
  semVer: string;
  minOS: string;
  urls: URLScheme[];
}

function getLabel(info: NSDictionary<StringLike, NSObject>) {
  for (const key of ["CFBundleDisplayName", "CFBundleName"]) {
    const value = info.objectForKey_(key);
    if (value) return value.toString();
  }

  return (
    info.objectForKey_("CFBundleAlternateNames")?.firstObject()?.toString() ||
    "N/A"
  );
}

// collect URL schemes
interface RawURLScheme {
  CFBundleURLName: string;
  CFBundleURLSchemes: string[];
  CFBundleTypeRole: string;
}

function wrapURLScheme(raw: RawURLScheme): URLScheme {
  return {
    name: raw.CFBundleURLName,
    schemes: raw.CFBundleURLSchemes,
    role: raw.CFBundleTypeRole,
  };
}

export function basics(): BasicInfo {
  const main = ObjC.classes.NSBundle.mainBundle();
  const infoDict = main.infoDictionary() as NSDictionary<StringLike, NSObject>;

  // collect readable names
  const READABLE_NAME_MAPPING = {
    version: "CFBundleVersion",
    semVer: "CFBundleShortVersionString",
    minOS: "MinimumOSVersion",
  };

  type VersionInfoKeys = keyof typeof READABLE_NAME_MAPPING;
  type VersionInfoDict = Record<VersionInfoKeys, string>;

  const versions = Object.fromEntries(
    Object.entries(READABLE_NAME_MAPPING).map(([key, label]) => [
      key,
      infoDict.objectForKey_(label)?.toString() || "N/A",
    ]),
  ) as VersionInfoDict;

  return {
    tmp: Process.getTmpDir(),
    home: Process.getHomeDir(),
    label: getLabel(infoDict),
    id: main.bundleIdentifier().toString(),
    path: main.bundlePath().toString(),
    main: main.executablePath().toString(),
    urls: urls(),
    ...versions,
  };
}

export function urls(): URLScheme[] {
  const infoDict =
    ObjC.classes.NSBundle.mainBundle().infoDictionary() as NSDictionary<
      StringLike,
      NSObject
    >;
  const urlTypes = infoDict.objectForKey_("CFBundleURLTypes") as NSArray<
    NSDictionary<StringLike, NSObject>
  >;
  const rawUrls: RawURLScheme[] = urlTypes ? toJsArray(urlTypes) : [];
  return rawUrls.map(wrapURLScheme);
}

export function plist() {
  return toJS(ObjC.classes.NSBundle.mainBundle().infoDictionary());
}

export function plistReadable() {
  const NSPropertyListXMLFormat_v1_0 = 100;
  const NSUTF8StringEncoding = 4;
  const dict = ObjC.classes.NSBundle.mainBundle().infoDictionary();
  const xml =
    ObjC.classes.NSPropertyListSerialization.dataWithPropertyList_format_options_error_(
      dict,
      NSPropertyListXMLFormat_v1_0,
      0,
      NULL,
    ) as NSData;

  return ObjC.classes.NSString.alloc()
    .initWithData_encoding_(xml, NSUTF8StringEncoding)
    .toString() as string;
}

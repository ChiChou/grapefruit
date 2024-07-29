import { toJsArray, valueOf } from '../bridge/dictionary.js'
import { NSArray, NSDictionary, NSObject, StringLike } from '../bridge/foundation.js';
import { tmp, home } from '../lib/foundation.js'

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
  for (const key of ['CFBundleDisplayName', 'CFBundleName']) {
    const value = info.objectForKey_(key)
    if (value) return value.toString()
  }

  return info.objectForKey_('CFBundleAlternateNames')?.firstObject()?.toString() || 'N/A'
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
    role: raw.CFBundleTypeRole
  }
}

export function basics(): BasicInfo {
  const main = ObjC.classes.NSBundle.mainBundle()
  const infoDict = main.infoDictionary() as NSDictionary<StringLike, NSObject>

  // collect readable names
  const READABLE_NAME_MAPPING = {
    version: 'CFBundleVersion',
    semVer: 'CFBundleShortVersionString',
    minOS: 'MinimumOSVersion'
  }

  type VersionInfoKeys = keyof typeof READABLE_NAME_MAPPING
  type VersionInfoDict = Record<VersionInfoKeys, string>

  const versions = Object.fromEntries(
    Object.entries(READABLE_NAME_MAPPING).map(([key, label]) =>
      [key, infoDict.objectForKey_(label)?.toString() || 'N/A']
    )) as VersionInfoDict;

  const urlTypes = infoDict.objectForKey_('CFBundleURLTypes') as NSArray<NSDictionary<StringLike, NSObject>>;
  const rawUrls: RawURLScheme[] = urlTypes ? toJsArray(urlTypes) : [];
  const urls = rawUrls.map(wrapURLScheme);

  return {
    tmp: tmp(),
    home: home(),
    label: getLabel(infoDict),
    id: main.bundleIdentifier().toString(),
    path: main.bundlePath().toString(),
    main: main.executablePath().toString(),
    urls,
    ...versions,
  }
}

export function plist() {
  return valueOf(ObjC.classes.NSBundle.mainBundle().infoDictionary())
}

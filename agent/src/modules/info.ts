import { toJsArray, valueOf } from '../bridge/dictionary.js'
import { NSTemporaryDirectory, NSHomeDirectory } from '../lib/foundation.js'

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

export function basics(): BasicInfo {
  const main = ObjC.classes.NSBundle.mainBundle();
  const dict = main.infoDictionary();

  // collect bundle information
  const tmp = NSTemporaryDirectory()
  const home = NSHomeDirectory()

  const BUNDLE_ATTR_MAPPING = {
    id: 'bundleIdentifier',
    path: 'bundlePath',
    main: 'executablePath'
  }

  type MainBundleKeys = keyof typeof BUNDLE_ATTR_MAPPING
  type MainBundleDict = Record<MainBundleKeys, string>

  const partial: Partial<MainBundleDict> = {}
  for (const [key, method] of Object.entries(BUNDLE_ATTR_MAPPING))
    partial[key as MainBundleKeys] = main[method]().toString() as string

  // collect readable names
  const READABLE_NAME_MAPPING = {
    version: 'CFBundleVersion',
    semVer: 'CFBundleShortVersionString',
    minOS: 'MinimumOSVersion'
  }

  type VersionInfoKeys = keyof typeof READABLE_NAME_MAPPING
  type VersionInfoDict = Record<VersionInfoKeys, string>

  const versionInfo: Partial<VersionInfoDict> = {}
  for (const [key, label] of Object.entries(READABLE_NAME_MAPPING)) {
    const value = dict.objectForKey_(label)
    versionInfo[key as VersionInfoKeys] = value?.toString() || 'N/A'
  }

  let label = 'N/A'
  for (const key of ['CFBundleDisplayName', 'CFBundleName']) {
    const value = dict.objectForKey_(key)
    if (value) {
      label = value.toString()
      break
    }
  }

  if (label === 'N/A') {
    const alternatives = dict.objectForKey_('CFBundleAlternateNames')
    if (alternatives) {
      const value = alternatives.firstObject()
      if (value) {
        label = value.toString()
      }
    }
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

  const urlTypes = dict.objectForKey_('CFBundleURLTypes');
  const rawUrls: RawURLScheme[] = urlTypes ? toJsArray(urlTypes) : [];
  const urls = rawUrls.map(wrapURLScheme);

  return {
    tmp,
    home,
    label,
    urls,
    ...(versionInfo as VersionInfoDict),
    ...(partial as MainBundleDict),
  }
}

export function plist() {
  return valueOf(ObjC.classes.NSBundle.mainBundle().infoDictionary())
}

export function userDefaults() {
  // todo: return schema
  // todo: edit user defaults
  return valueOf(ObjC.classes.NSUserDefaults.standardUserDefaults().dictionaryRepresentation())
}

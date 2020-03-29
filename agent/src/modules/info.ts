import { valueOf } from '../lib/dict'
import { NSTemporaryDirectory, NSHomeDirectory } from '../lib/foundation'

const { NSBundle, NSUserDefaults } = ObjC.classes

type Info = { [key: string]: any }

export function info(): Info {
  const mainBundle = NSBundle.mainBundle()
  const json = valueOf(mainBundle.infoDictionary())
  const result: Info = {
    tmp: NSTemporaryDirectory(),
    home: NSHomeDirectory(),
    json,
    urls: []
  }

  const BUNDLE_ATTR_MAPPING = {
    id: 'bundleIdentifier',
    bundle: 'bundlePath',
    binary: 'executablePath'
  }

  for (const [key, method] of Object.entries(BUNDLE_ATTR_MAPPING))
    result[key] = mainBundle[method]().toString()

  if ('CFBundleURLTypes' in json) {
    result.urls = json.CFBundleURLTypes.map((item: { [key: string]: string }) => ({
      name: item.CFBundleURLName,
      schemes: item.CFBundleURLSchemes,
      role: item.CFBundleTypeRole
    }))
  }

  const READABLE_NAME_MAPPING = {
    name: 'CFBundleDisplayName',
    version: 'CFBundleVersion',
    semVer: 'CFBundleShortVersionString',
    minOS: 'MinimumOSVersion'
  }

  for (const [key, label] of Object.entries(READABLE_NAME_MAPPING))
    result[key] = json[label] || 'N/A'

  return result
}


export function userDefaults() {
  return valueOf(NSUserDefaults.alloc().init().dictionaryRepresentation())
}

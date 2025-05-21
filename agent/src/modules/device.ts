import ObjC from 'frida-objc-bridge'

export function info() {
  const keys = ['name', 'systemVersion', 'buildVersion', 'systemName', 'model', 'localizedModel']
  const device = ObjC.classes.UIDevice.currentDevice()
  const result: {[key: string]: string } = {}

  for (const key of keys)
    result[key] = device[key]() + ''
  return result
}

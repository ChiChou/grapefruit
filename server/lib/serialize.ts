import { Icon, Device, Application } from 'frida'
import { DeviceType } from 'frida/dist/device'

import { buggy } from './workaround'

export function icon(icon?: Icon): object {
  if (!icon) return
  const { height, width, image, format } = icon
  return { width, height, image: image.toString('base64'), format }
}

export function device(dev: Device): object {
  const { name, id, type } = dev
  const removable = dev.type === DeviceType.Remote && dev.name !== 'Local Socket'
  return { name, id, icon: buggy ? undefined : icon(dev.icon), type, removable }
}

export function app(app: Application): object {
  const { name, parameters, identifier, pid } = app
  const ico = parameters.icons?.pop()
  return {
    name,
    pid,
    identifier,
    icon: ico ? icon(ico) : undefined,
  }
}

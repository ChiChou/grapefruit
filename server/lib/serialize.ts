import { Icon, Device, Application } from 'frida'
import { DeviceType } from 'frida/dist/device'

export function icon(icon?: Icon): object {
  if (!icon) return
  const { height, width, image, format } = icon
  return { width, height, image: image.toString('base64'), format }
}

export function device(dev: Device): object {
  const { name, id, type } = dev
  const removable = dev.type === DeviceType.Remote && dev.name !== 'Local Socket'
  return { name, id, icon: icon(dev.icon), type, removable }
}

export function app(app: Application): object {
  const { name, identifier, pid } = app
  return {
    name,
    pid,
    identifier,
  }
}

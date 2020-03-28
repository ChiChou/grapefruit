import { Icon, Device, Application } from 'frida'

export function icon(icon?: Icon): object {
  if (!icon) return
  const { pixels, height, width, rowstride } = icon
  return { width, height, rowstride, pixels: pixels.toString('base64') }
}

export function device(dev: Device): object {
  const { name, id, type } = dev
  return { name, id, icon: icon(dev.icon), type }
}

export function app(app: Application): object {
  const { name, smallIcon, largeIcon, identifier, pid } = app
  return {
    name,
    pid,
    identifier,
    smallIcon: icon(smallIcon),
    largeIcon: icon(largeIcon),
  }
}

import { Icon, Device, Application } from 'frida'
import { DeviceType } from 'frida/dist/device'

const major = (() => {
  // a workaround for
  // https://github.com/ChiChou/Grapefruit/issues/20
  // https://github.com/frida/frida-node/issues/61

  const [major, ] = process.versions.node.split('.')
  return parseInt(major)
})()

export function icon(icon?: Icon): object {
  if (!icon) return
  const { pixels, height, width, rowstride } = icon
  return { width, height, rowstride, pixels: pixels.toString('base64') }
}

export function device(dev: Device): object {
  const { name, id, type } = dev
  const removable = dev.type === DeviceType.Remote && dev.name !== 'Local Socket'
  return { name, id, icon: major > 12 ? undefined : icon(dev.icon), type, removable }
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

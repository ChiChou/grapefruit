import { Icon, Device, Application } from 'frida'
import { DeviceType } from 'frida/dist/device'

export interface IconInfo {
  width: number;
  height: number;
  image: string;
  format: 'rgba' | 'png'
}

export interface DeviceInfo {
  name: string;
  id: string;
  icon: IconInfo;
  type: DeviceType;
  removable: boolean;
}

export interface AppInfo {
  name: string;
  pid: number;
  identifier: string;
}

export function icon(icon?: Icon): IconInfo {
  if (!icon) return
  const { height, width, image, format } = icon
  return { width, height, image: image.toString('base64'), format }
}

export function device(dev: Device): DeviceInfo {
  const { name, id, type } = dev
  const removable = dev.type === DeviceType.Remote && dev.name !== 'Local Socket'
  return { name, id, icon: icon(dev.icon), type, removable }
}

export function app(app: Application): AppInfo {
  const { name, identifier, pid } = app
  return {
    name,
    pid,
    identifier,
  }
}

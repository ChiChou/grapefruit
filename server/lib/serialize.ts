import { Device, Application } from 'frida'
import { DeviceType } from 'frida'

export function device(dev: Device): object {
  const { name, id, type } = dev
  const removable = dev.type === DeviceType.Remote && dev.name !== 'Local Socket'
  return { name, id, type, removable }
}

export function app(app: Application): object {
  const { name, identifier, pid } = app

  return {
    name,
    pid,
    identifier
  }
}

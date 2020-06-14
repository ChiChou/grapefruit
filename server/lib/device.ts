import { AppNotFoundError, EarlyInstrumentError, DeviceNotFoundError, InvalidDeviceError, VersionMismatchError } from './error'
import { Device, Session, enumerateDevices, getUsbDevice, getDevice } from 'frida'
import { retry } from './utils'

import * as serialize from './serialize'
import { DeviceType } from 'frida/dist/device'

export async function match(prefix: string): Promise<Device> {
  const list = await enumerateDevices()
  const dev = list.find(d => d.id.startsWith(prefix))
  if (dev) return dev
  throw new DeviceNotFoundError(prefix)
}

export class ExDevice {
  constructor(public device: Device) {}

  async start(bundle: string): Promise<Session> {
    const apps = await this.device.enumerateApplications()
    const app = apps.find(item => item.identifier === bundle)
    if (!app) throw new AppNotFoundError(bundle)
    if (app.pid) {
      const front = await this.device.getFrontmostApplication()
      if (front && front.pid === app.pid) {
        return await this.device.attach(app.name)
      } else {
        await this.device.kill(app.pid)
        return await this.launch(bundle)
      }
    }
    return this.launch(bundle)
  }

  async open(bundle: string, url: string): Promise<number> {
    const pid = await this.device.spawn([bundle], { url })
    await this.device.resume(pid)
    return pid
  }

  async launch(bundle: string): Promise<Session> {
    const pid = await this.device.spawn(bundle)
    const session = await this.device.attach(pid)
    await this.device.resume(pid)

    const probe = await session.createScript(`
      Module.ensureInitialized('Foundation'); rpc.exports.ok = function() { return true }`)

    await probe.load()
    const ok = await retry(probe.exports.ok.bind(probe.exports))
    if (!ok) throw new EarlyInstrumentError(bundle)
    return session
  }

  async apps(): Promise<object[]> {
    const list = await this.device.enumerateApplications()
    return list.map(serialize.app)
  }

  valueOf(): object {
    return serialize.device(this.device)
  }

  get host(): string {
    const prefix = 'remote@'
    if (this.device.type === DeviceType.Remote && this.device.id.startsWith(prefix))
      return this.device.id.slice(prefix.length)
    return null
  }
}

export function wrap(device: Device): ExDevice {
  return new ExDevice(device)
}

export function tryGetDevice(id: string): Promise<Device> {
  try {
    return id === 'usb' ? getUsbDevice() : getDevice(id)
  } catch (ex) {
    if (ex.message.startsWith('Unable to connect to remote frida-server'))
      throw new InvalidDeviceError(id)
    if (ex.message.startsWith('Unable to communicate with remote frida-server'))
      throw new VersionMismatchError(ex.message)
    else
      throw ex
  }
}
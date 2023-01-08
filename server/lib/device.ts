import { Device, Session, enumerateDevices, getUsbDevice, getDevice, getLocalDevice } from 'frida'
import { DeviceType } from 'frida/dist/device'

import * as serialize from './serialize'
import { launch, simulators } from './simctl'
import { SimulatorInfo } from '../api/sim'
import { AppNotFoundError, EarlyInstrumentError, DeviceNotFoundError, InvalidDeviceError, VersionMismatchError } from './error'

export async function match(prefix: string): Promise<Device> {
  const list = await enumerateDevices()
  const dev = list.find(d => d.id.startsWith(prefix))
  if (dev) return dev
  throw new DeviceNotFoundError(prefix)
}

export class ExDevice {
  constructor(public device: Device) { }

  async start(bundle: string): Promise<Session> {
    const apps = await this.device.enumerateApplications({ identifiers: [bundle] })
    if (!apps.length) throw new AppNotFoundError(bundle)
    const app = apps[0]
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

  async launch(bundle: string): Promise<Session> {
    const pid = await this.device.spawn(bundle)
    const session = await this.device.attach(pid)
    await this.device.resume(pid)
    return session
  }

  async apps(): Promise<object[]> {
    const list = await this.device.enumerateApplications()
    return list.map(serialize.app)
  }

  valueOf(): serialize.DeviceInfo {
    return serialize.device(this.device)
  }

  get host(): string {
    const prefix = 'remote@'
    if (this.device.type === DeviceType.Remote && this.device.id.startsWith(prefix))
      return this.device.id.slice(prefix.length)
    return null
  }
}

export class Simulator extends ExDevice {
  constructor(public device: Device, public info: SimulatorInfo) {
    super(device)
  }

  async start(bundle: string): Promise<Session> {
    const pid = await launch(this.info.udid, bundle)
    return this.device.attach(pid)
  }

  valueOf(): serialize.DeviceInfo {
    const val = super.valueOf()
    const { udid, name } = this.info
    return Object.assign(val, {
      udid,
      name
    })
  }
}

export function wrap(device: Device): ExDevice {
  return new ExDevice(device)
}

export async function getSimulator(id: string): Promise<Simulator> {
  const sims = await simulators()
  const sim = sims.find(s => s.udid == id)
  if (!sim) return Promise.reject(new Error(`Simulator ${id} not found`))
  return Promise.resolve(new Simulator(await getLocalDevice(), sim))
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
import frida from 'frida'
import { DeviceNotFoundError, AppAttachError } from './error'
import { retry } from './utils'


export async function match(prefix: string): Promise<frida.Device> {
  const list = await frida.enumerateDevices()
  const dev = list.find(d => d.id.startsWith(prefix))
  if (dev) return dev
  throw new DeviceNotFoundError(prefix)
}

const PROBE_SCRPT = `Module.ensureInitialized('Foundation'); rpc.exports.ok = function() { return true }`;

export async function spawn(dev: frida.Device, app: frida.Application): Promise<frida.Session> {
  const pid = await dev.spawn([app.identifier])
  const session = await dev.attach(pid)
  await dev.resume(pid).catch()
  const probeScript = await session.createScript(PROBE_SCRPT)

  await probeScript.load()
  try {
    const ok = await retry(probeScript.exports.ok.bind(probeScript.exports))
    if (!ok) throw new AppAttachError(app.identifier)
  } catch (ex) {
    if (/FBSOpenApplicationErrorDomain error 7/.exec(ex)) throw Error('device is locked')
    console.error(ex)
    await session.detach()
    throw new AppAttachError(app.identifier)
  }
  return session
}
import * as frida from 'frida'
import http from 'http'

import io from 'socket.io'
import { wrap } from './device'
import { connect, proxy } from './rpc'

const socket = io()
const devices = socket.of('/devices')
const session = socket.of('/session')

const mgr = frida.getDeviceManager()
const connected = new Map()

session.on('connection', async (socket) => {
  const { device, bundle } = socket.handshake.query
  const dev = await frida.getDevice(device)
  const ex = wrap(dev)
  const session = await ex.launch(bundle)

  // no more enableJIT()
  session.detached.connect((reason) => {
    socket.emit('detached', reason)
    socket.disconnect(true)
  })

  socket
    .on('detach', () => socket.disconnect())
    .on('kill', async (_data, ack) => {
      const { pid } = session
      await session.detach()
      await dev.kill(pid)
      ack(true)
      socket.disconnect()
    })
    .on('disconnect', async () => session.detach())

  const agent = await connect(session)
  const rpc = proxy(agent)

  socket.on('rpc', async (data, ack) => {
    if (!(typeof data === 'object' && 'method' in data))
      return
    
    const { method } = data
    const args = data.args || []

    try {
      const result = await rpc(method, ...args)
      ack({ status: 'ok', data: result })
    } catch (err) {
      ack({ status: 'error', error: `${err}` })
      console.error('Uncaught RPC error', err.stack || err)
      console.error('method:', method, 'args:', args)
    }
  })

  agent.destroyed.connect(() => {
    socket.emit('SCRIPT_DESTROYED')
    socket.disconnect(true)
  })

  // agent.message.connect((message, data) => {
  //   if (message.type === 'error') {
  //     console.error('error message from frida'.red)
  //     console.error((message.stack || message).red)
  //   } else if (message.type === 'send') {
  //     // todo
  //   }
  // })

  await agent.load()

  socket.emit('ready')
})

export function attach(server: http.Server): void {
  socket.attach(server)

  /* eslint @typescript-eslint/explicit-function-return-type: 0 */
  const event = (tag: string) => (device: frida.Device) =>
    devices.emit(tag, wrap(device).valueOf())

  const added = event('DEVICE_ADD')
  const removed = event('DEVICE_REMOVE')
  mgr.added.connect(added)
  mgr.removed.connect(removed)
  connected.set(server, [added, removed])
}

export function detach(server): void {
  const [added, removed] = connected.get(server)
  mgr.added.disconnect(added)
  mgr.removed.disconnect(removed)
}

export const broadcast = session.emit.bind(session)
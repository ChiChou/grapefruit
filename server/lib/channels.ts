import * as frida from 'frida'
import http from 'http'

import io from 'socket.io'
import { wrap, tryGetDevice } from './device'
import { connect, proxy } from './rpc'

const mgr = frida.getDeviceManager()

interface RPCPacket {
  method: string;
  args?: object[];
}

export default class Channel {
  socket: io.Server
  devices: io.Namespace
  session: io.Namespace

  constructor(srv: http.Server) {
    this.socket = io(srv)
    this.devices = this.socket.of('/devices')
    this.session = this.socket.of('/session')
    
    mgr.added.connect(this.added)
    mgr.removed.connect(this.removed)
  }

  added(device: frida.Device): void {
    this.devices.emit('DEVICE_ADD', wrap(device).valueOf())
  }

  removed(device: frida.Device): void {
    this.devices.emit('DEVICE_ADD', wrap(device).valueOf())
  }

  handleEvents(): void {
    this.session.on('connection', async (socket) => {
      const { device, bundle } = socket.handshake.query
      const dev = await tryGetDevice(device)
      const ex = wrap(dev)
      const session = await ex.launch(bundle)

      session.detached.connect((reason) => {
        socket.emit('detached', reason)
        socket.disconnect(true)
      })

      socket.on('bye', () => {
        
      }).on('disconnect', () => {
        // todo:
      }).on('kill', async (data, ack) => {
        const { pid } = session
        await session.detach()
        await dev.kill(pid)
        ack(true)
        socket.disconnect()
      })

      const agent = await connect(session)
      const rpc = proxy(agent)

      socket.on('rpc', async (data: RPCPacket, ack) => {
        if (typeof data !== 'object' || typeof data.method !== 'string' || !Array.isArray(data.args))
          return
        
        const { method, args } = data
        try {
          const result = await rpc(method, ...args)
          ack({ status: 'ok', data: result })
        } catch(err) {
          ack({ status: 'error', error: `${err}` })
          // todo: log
          console.error('Uncaught RPC error', err.stack || err)
          console.error('method:', method, 'args:', args)
        }
      })

      agent.destroyed.connect(() => {
        socket.emit('SCRIPT_DESTROYED')
        socket.disconnect(true)
      })

      socket.emit('READY')
    })
  }
}

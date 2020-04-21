/* eslint-disable @typescript-eslint/no-explicit-any */
import * as frida from 'frida'
import http from 'http'

import io from 'socket.io'
import { wrap, tryGetDevice } from './device'
import { connect, proxy } from './rpc'
import { DevicesChangedHandler } from 'frida'

const mgr = frida.getDeviceManager()

interface RPCPacket {
  method: string;
  args?: object[];
}

export default class Channels {
  socket: io.Server
  devices: io.Namespace
  session: io.Namespace
  changedSignal: DevicesChangedHandler

  constructor(srv: http.Server) {
    this.socket = io(srv)
    this.devices = this.socket.of('/devices')
    this.session = this.socket.of('/session')
  }

  onchange(): void {
    this.devices.emit('deviceChanged')
  }

  disconnect(): void {
    mgr.changed.disconnect(this.changedSignal)
  }

  connect(): void {
    this.changedSignal = this.onchange.bind(this)
    mgr.changed.connect(this.changedSignal)

    this.session.on('connection', async (socket) => {
      const { device, bundle } = socket.handshake.query
      let dev, session
      try {
        dev = await tryGetDevice(device)
        session = await wrap(dev).launch(bundle)
      } catch(e) {
        socket.emit('exception', e.toString())
        socket.disconnect()
      }

      session.detached.connect((reason) => {
        socket.emit('detached', reason)
        socket.disconnect(true)
      })

      socket.on('disconnect', async () => {
        await session.detach()
      }).on('kill', async (data, ack) => {
        const { pid } = session
        await session.detach()
        await dev.kill(pid)
        ack(true)
        socket.disconnect()
      })

      const agent = await connect(session)
      await agent.load()
      const rpc = proxy(agent)

      socket.on('rpc', async (method: string, args: any[], ack) => {
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
        socket.emit('scriptDestroyed')
        socket.disconnect(true)
      })

      socket.emit('ready')
    })
  }
}

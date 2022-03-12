/* eslint-disable @typescript-eslint/no-explicit-any */
import * as frida from 'frida'
import http from 'http'

import { Server, Namespace } from 'socket.io'
import REPL from './repl'
import * as transfer from './transfer'
import { wrap, tryGetDevice } from './device'
import { connect, proxy } from './rpc'

import { MessageType } from 'frida/dist/script'

const mgr = frida.getDeviceManager()

interface RPCPacket {
  method: string;
  args?: object[];
}

export default class Channels {
  socket: Server
  devices: Namespace
  session: Namespace
  changedSignal: frida.DevicesChangedHandler

  constructor(srv: http.Server) {
    this.socket = new Server(srv)
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
      let dev: frida.Device, session: frida.Session

      if (typeof device !== 'string' || typeof bundle !== 'string') {
        socket.emit('exception', 'invalid parameter type')
        socket.disconnect()
        return
      }

      try {
        dev = await tryGetDevice(device)
        session = await wrap(dev).start(bundle)
      } catch (e) {
        socket.emit('exception', e.toString())
        socket.disconnect()
        return
      }

      // todo: preferences
      const { pid } = session

      session.detached.connect((reason: frida.SessionDetachReason, crash) => {
        // {
        //   ApplicationRequested = "application-requested",
        //   ProcessReplaced = "process-replaced",
        //   ProcessTerminated = "process-terminated",
        //   ServerTerminated = "server-terminated",
        //   DeviceLost = "device-lost"
        // }
        console.error('session detached:', reason, crash)
        if (reason === 'application-requested') return
        if (reason === 'process-terminated') {
          socket.emit('console', 'error', `app crash, reason: ${reason}\ndetail:\n${crash}`)
          socket.emit('crash', reason, crash)
        }
        socket.emit('detached', reason)
        socket.disconnect(true)
      })

      const agent = await connect(session)
      agent.logHandler = (level, text): void => {
        socket.emit('console', level, text)
        console.log(`[frida ${level}]`, text)
      }

      agent.message.connect(async (msg, data) => {
        if (msg.type === MessageType.Send) {
          const { subject } = msg.payload
          if (subject === 'download') {
            const { event, session } = msg.payload
            if (event === 'begin') {
              const { size, path } = msg.payload
              transfer.begin(session, size, path)
            } else if (event === 'data') {
              transfer.push(session, data)
              await agent.post({ type: 'ack' })
            } else if (event === 'end') {
              transfer.end(session)
            }
          } else if (subject === 'exception') {
            console.error('App exception:')
            console.error(msg.payload.detail)
          }
        }
      })

      await agent.load()
      const rpc = proxy(agent)

      socket.on('disconnect', async () => {
        try {
          agent.post({ type: 'dispose' })
          await session.detach()
          // eslint-disable-next-line no-empty
        } catch (e) {

        }
      }).on('kill', async () => {
        session.detach().catch()
        await dev.kill(pid)
        socket.disconnect()
      }).on('rpc', async (method: string, args: any[], ack) => {
        try {
          const result = await rpc(method, ...args)
          ack({ status: 'ok', data: result })
        } catch (err) {
          ack({ status: 'error', error: `${err.message}` })
          socket.emit('console', 'error', `RPC Error: \n${err.stack}`)
          console.error('Uncaught RPC error', err.stack || err)
          console.error('method:', method, 'args:', args)
        }
      })

      const repl = new REPL(session)

      repl
        .on('destroyed', ({ uuid }) => {
          console.log('implement me: script destroy')
          socket.emit('userscriptdestroy')
        })
        .on('scripterror', (err: object) => {
          console.log('implement me: script error')
          socket.emit('scripterror', err)
        })
        .on('scriptmessage', () => {
          console.log('implement me: script message')
        })
        .on('console', (uuid: string, level: string, text: string) => {
          socket.emit('console', level, `(user script) ${text}`)
        })

      socket.on('userscript', async (source: string, uuid: string, ack: Function) => {
        ack(await repl.eval(source, uuid))
      })

      socket.on('removescript', async (uuid: string, ack: Function) => {
        try {
          await repl.remove(uuid)
        } catch(e) {
          console.error(e)
          ack(false)
          return
        }
        ack(true)
      })

      agent.destroyed.connect(() => {
        console.error('script destroyed')
      })

      socket.emit('ready')
    })
  }
}

/* eslint @typescript-eslint/no-explicit-any: 0 */
/* eslint no-useless-constructor: 0 */

import { io, Socket } from 'socket.io-client'
import Vue from 'vue'
import { Route } from 'vue-router'
import { DialogProgrammatic as Dialog } from 'buefy'

import * as regulation from './regulation'
import { RPC, WSEvent, Context, RpcResponse, Options } from './wsrpc.d'

const ctx: Context = {}

export type Handler = (...args: any[]) => void;

class Lazy {
  chain: string[] = []
  ready = false
  private _pending: Handler[] = []

  constructor(public socket: Socket) {
    socket.on('ready', () => {
      this.ready = true
      this._pending.forEach(f => f())
      this._pending = []
    })
  }

  ensureReady(): Promise<boolean> {
    if (this.ready) return Promise.resolve(true)
    return new Promise((resolve) =>
      this._pending.push(() =>
        resolve(true)
      ))
  }

  push(name: string): Lazy {
    this.chain.push(name)
    return this
  }

  apply(argArray: any): Promise<any> {
    let name: string, args: any
    if (this.chain.length) {
      name = this.chain.join('/')
      args = argArray
    } else {
      [name, ...args] = argArray
    }
    this.chain = []
    return this.ensureReady().then(() => {
      return new Promise((resolve, reject) => {
        let ok = false
        this.socket.emit('rpc', name, args, (response: RpcResponse) => {
          if (response.status === 'ok') {
            ok = true
            resolve(response.data)
          } else {
            reject(new Error(response.error))
          }
        })

        setTimeout(() => {
          if (!ok) {
            reject(new Error('Request timed out'))
          }
        }, 10000)
      })
    })
  }
}

function wrap(socket: Socket): RPC {
  const lazy = new Lazy(socket)
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  const p = new Proxy(() => {}, {
    get(target: any, name: string): RPC {
      lazy.push(name)
      return p
    },
    apply(target: any, thisArg: any, argArray?: any): any {
      return lazy.apply(argArray)
    }
  })

  return p
}

class WS {
  private _ready = false
  private _pending: Set<Handler> = new Set()

  constructor(public socket: Socket) {
    this.socket.on('ready', () => {
      this._pending.forEach(cb => cb())
      this._pending.clear()
    })
  }

  ready() {
    if (this._ready) return Promise.resolve(true)
    return new Promise(resolve => this._pending.add(resolve))
  }

  on(event: WSEvent, cb: Handler) {
    if (event === 'ready') {
      if (this._ready) {
        Vue.nextTick(() => cb())
      } else {
        this._pending.add(cb)
      }
    } else {
      this.socket.on(event, cb)
    }
    return this
  }

  send(event: string, ...args: any[]): Promise<any> {
    return new Promise((resolve) => this.socket.emit(event, ...args, resolve))
  }

  once(event: string, cb: Handler) {
    this.ready().then(() => this.socket.once(event, cb))
    return this
  }

  off(event: string, cb: Handler) {
    this.ready().then(() => this.socket.off(event, cb))
    return this
  }
}

function install(V: typeof Vue, opt: Options): void {
  const { router } = opt
  const isWorkspace = (route: Route) => 'device' in route.params && 'bundle' in route.params

  router.afterEach((to, from) => {
    const previous = isWorkspace(from)
    const current = isWorkspace(to)
    if (!previous && current) {
      const { device, bundle } = to.params

      if (regulation.check(bundle)) {
        Dialog.alert({
          title: 'Warning',
          hasIcon: true,
          type: 'is-warning',
          message: 'Sorry, due to local regulation restrictions, we are not able to work on this app',
          onConfirm() { router.go(-1) }
        })

        return
      }

      const socket = io('/session', { query: { device, bundle }, transports: ['websocket'], auth: { token: V.prototype.$token } })

      V.prototype.$rpc = wrap(socket)
      V.prototype.$ws = new WS(socket)
      ctx.socket = socket
    } else if (previous && !current) {
      if (!ctx.socket) {
        throw new Error('invalid state, expected socket !== null')
      }
      ctx.socket.disconnect()
      V.prototype.$rpc = undefined
      V.prototype.$ws = undefined
    }

    // todo: handle disconnection
  })
}

export default { install }

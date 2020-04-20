/* eslint @typescript-eslint/no-explicit-any: 0 */
/* eslint no-useless-constructor: 0 */

import * as io from 'socket.io-client'
import Vue from 'vue'
import VueRouter, { Route } from 'vue-router'

import { RPC } from './wsrpc.d'

interface Options {
  router: VueRouter;
}

interface Context {
  socket?: SocketIOClient.Socket;
  proxy?: RPC;
}

interface RpcResponse {
  status: 'ok' | 'error';
  data: any;
  error: string;
}

const ctx: Context = {}

class Lazy {
  chain: string[] = []
  constructor(public socket: SocketIOClient.Socket) { }

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
      }, 5000)
    })
  }
}

function wrap(socket: SocketIOClient.Socket): RPC {
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

function install(V: typeof Vue, opt: Options) {
  const { router } = opt
  const needs = (route: Route) => 'device' in route.params && 'bundle' in route.params
  const pending: Set<Function> = new Set()
  router.afterEach((to, from) => {
    const previous = needs(from)
    const current = needs(to)
    if (!previous && current) {
      console.debug('connect')
      const { device, bundle } = to.params
      const socket = io.connect('/session', { query: { device, bundle } })
      socket.on('ready', async() => {
        V.prototype.$rpc = wrap(socket)
        V.prototype.ws = (event: string, ...args: any) =>
          new Promise((resolve) =>
            ctx.socket?.emit(event, args, resolve))
        pending.forEach(cb => cb())
        pending.clear()
      })
      ctx.socket = socket
    } else if (previous && !current) {
      if (!ctx.socket) {
        throw new Error('invalid state, expected socket !== null')
      }
      console.debug('disconnect')
      ctx.socket.disconnect()
      V.prototype.$rpc = undefined
      V.prototype.ws = undefined
    }
  })

  V.prototype.rpcReady = function(): Promise<boolean> {
    if (ctx.socket && ctx.proxy) {
      return Promise.resolve(true)
    }
    return new Promise((resolve) => pending.add(() => resolve(true)))
  }
}

export default { install }

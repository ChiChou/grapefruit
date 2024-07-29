/* eslint @typescript-eslint/no-explicit-any: 0 */
/* eslint no-useless-constructor: 0 */

// todo: rewrite this module

import { Socket } from 'socket.io-client'

export type RPC = {
  [key: string]: RPC;
  (...args: any): any;
}

type WSEvent = 'ready' | 'destroyed' |
  'exception' | 'detached' | 'console' | 'crash' |
  'download' | 'delivery' | 'richconsole'

interface RpcResponse {
  status: 'ok' | 'error';
  data: any;
  error: string;
}

type Handler = (...args: any[]) => void;

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
      name = this.chain.join('.')
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

export function useRPC(socket: Socket): RPC {
  const lazy = new Lazy(socket)
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  const p = new Proxy(() => { }, {
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
/* eslint @typescript-eslint/no-explicit-any: 0 */
/* eslint no-useless-constructor: 0 */

// todo: rewrite this module

import { Socket } from 'socket.io-client'
import { RemoteRPC } from './rpc/registry';

export type WSEvent = 'ready' | 'destroyed' |
  'exception' | 'detached' | 'console' | 'crash' |
  'download' | 'delivery' | 'richconsole'

interface RpcResponse {
  status: 'ok' | 'error';
  data: any;
  error: string;
}

class Lazy {
  prefix: string[] = []
  ready = false

  constructor(public socket: Socket) {
    socket.once('ready', () => { this.ready = true })
  }

  push(name: string): Lazy {
    this.prefix.push(name)
    return this
  }

  apply(argArray: any): Promise<any> {
    let name: string, args: any
    if (this.prefix.length) {
      name = this.prefix.join('.')
      args = argArray
    } else {
      [name, ...args] = argArray
    }
    this.prefix = []
    const call = new Promise((resolve, reject) => {
      const execute = () => {
        this.socket.emit('rpc', name, args, (response: RpcResponse) => {
          if (response.status === 'ok') {
            resolve(response.data)
          } else {
            reject(new Error(response.error))
          }
        })
      }

      if (this.ready) {
        execute()
      } else {
        this.socket.once('ready', execute)
      }
    })

    const timeout = new Promise((_, reject) => setTimeout(() => reject, 10000))
    return Promise.race([call, timeout])
  }
}

export function useRPC(socket: Socket): RemoteRPC {
  const lazy = new Lazy(socket)
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  const p = new Proxy(() => { }, {
    get(target: any, name: string): any {
      lazy.push(name)
      return p
    },
    apply(target: any, thisArg: any, argArray?: any): any {
      return lazy.apply(argArray)
    }
  })

  return p
}
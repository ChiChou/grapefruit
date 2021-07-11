/* eslint @typescript-eslint/no-use-before-define: 0 */
/* eslint @typescript-eslint/no-explicit-any: 0 */

import path from 'path'
import fs from 'fs'
import { promisify } from 'util'

import { Session, Script } from 'frida'

const readFile = promisify(fs.readFile)


export async function connect(session: Session): Promise<Script> {
  const filename = path.join(__dirname, '..', '..', 
    process.env.NODE_ENV === 'development' ? '.' : '..', 'agent', 'dist.js')
  const source = await readFile(filename, 'utf8')
  const script = await session.createScript(source)

  return script
}

class Lazy {
  chain: string[] = []
  constructor(public script: Script) { }

  push(method: string): Lazy {
    this.chain.push(method)
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
    return this.script.exports.invoke(name, args)
  }
}

export type RPC = {
  [key: string]: RPC;
  (...args: any): any;
}

export function proxy(script: Script): RPC {
  const ctx = new Lazy(script)
  // eslint-disable-next-line @typescript-eslint/no-empty-function
  const p = new Proxy(() => {}, {
    get(target: any, name: string): RPC {
      ctx.push(name)
      return p
    },
    apply(target: any, thisArg: any, argArray?: any): any {
      return ctx.apply(argArray)
    }
  })

  return p
}

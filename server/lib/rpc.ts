/* eslint @typescript-eslint/no-use-before-define: 0 */

import path from 'path'
import fs from 'fs'
import { promisify } from 'util'

import { Session, Script, Device } from 'frida'

const readFile = promisify(fs.readFile)


export async function connect(session: Session): Promise<Script> {
  await session.enableJit()

  const filename = path.join(__dirname, '..', '..', 'agent', 'dist.js')
  const source = await readFile(filename, 'utf8')
  const script = await session.createScript(source)

  return script
}

export interface RPC {
  [key: string]: any;
}

export function proxy(script: Script): RPC {
  const func = script.exports.invoke.bind(script.exports)
  let chain = []

  const handlers = {
    get: recursiveGetter,
    apply,
  }

  /* eslint @typescript-eslint/explicit-function-return-type: 0 */
  function apply(_: Device, _thisArg, argArray) {
    let name: string, args
    if (chain.length) {
      name = chain.join('/')
      args = argArray
    } else {
      [name, ...args] = argArray
    }
    chain = []
    return func(name, args)
  }

  function recursiveGetter(target: Device, name: string) {
    chain.push(name)
    return new Proxy(target, handlers)
  }

  return new Proxy(func, handlers)
}

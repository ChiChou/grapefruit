import { EventEmitter } from 'events'
import { promises as fs } from 'fs'

import { Session, Script, MessageType } from 'frida'
import path from 'path'

type status = 'ok' | 'failed'

interface Result {
  status: status;
  uuid: string;
  type?: string;
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  value?: any;
  error?: Error;
}

export default class REPL extends EventEmitter {
  scripts: Map<string, Script> = new Map()
  cache: string

  constructor(public session: Session) {
    super()
  }

  async source(): Promise<string> {
    if (this.cache) return Promise.resolve(this.cache)
    const filename = path.join(__dirname, '..', '..', 
      process.env.NODE_ENV === 'development' ? '.' : '..', 'agent', 'eval.js')
    const buf = await fs.readFile(filename)
    return buf.toString()
  }

  public async eval(source: string): Promise<Result> {
    const { session } = this
    const uuid = Math.random().toString(16).slice(2)
    const script = await session.createScript(await this.source())
    script.destroyed.connect(() => {
      // todo typescript interface
      this.emit('destroyed', { uuid })
    })

    script.message.connect((message, data) => {
      if (message.type === MessageType.Error) {        
        const { columnNumber, description, fileName, lineNumber, stack } = message
        this.emit('scripterror', {
          columnNumber, description, fileName, lineNumber, stack
        })
      } else {
        const { payload } = message
        // todo: typescript interface
        if (payload?.subject === 'console.message') {
          this.emit('console', uuid, payload.level, payload.args)
        } else { 
          this.emit('scriptmessage', {
            uuid,
            payload,
            data
          })
        }
      }
    })

    await script.load()

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let result: any
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      result = await script.exports.eval(source) as ArrayBuffer | { type: string; value: any }
    } catch(e) {
      console.error('Failed to execute user script')
      console.error(e)
      return {
        status: 'failed',
        uuid
      }
    }
  
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    let type: string, value: any
    if (result instanceof Buffer) {
      type = 'arraybuffer'
      value = result.buffer

      // hex dump
      // value = '<Buffer ' + (
      //   value.toString('hex')
      //     .replace(/[\dA-Fa-f]{2}/g, s => s + ' ')
      //     .replace(/ $/, '>')
      //   )
    } else {
      [type, value] = result
    }

    if (type === 'error') {
      console.error('User frida script exception:')
      console.error(value.stack || value)
      return {
        uuid,
        status: 'failed',
        error: new Error(value),
      }
    }

    this.scripts.set(uuid, script)
    return {
      status: 'ok',
      uuid,
      type,
      value,
    }
  }

  public async remove(uuid: string): Promise<void> {
    if (!this.scripts.has(uuid))
      throw new Error(`script not found: ${uuid}`)

    const script = this.scripts.get(uuid)
    this.scripts.delete(uuid)
    return script.unload()
  }

  public async destroy(): Promise<void> {
    for (const script of this.scripts.values()) script.unload()
    this.scripts.clear()
  }
}


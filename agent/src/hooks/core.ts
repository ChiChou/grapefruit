import ObjC from 'frida-objc-bridge'

interface Signature {
  args: string[];
  ret?: string;
}

const subject = 'hook'
const now = () => (new Date()).getTime()
const readable = (type: string, arg: NativePointer) => (type === 'char *' ? arg.readUtf8String() : arg)
const hooked = new Map<string, InvocationListener>()

export function hook(mod: string, symbol: string, signature: Signature) {
  const library = Process.findModuleByName(mod)
  if (!library) throw new Error(`Module ${mod} not loaded`)

  const p = library.findExportByName(symbol)
  if (!p) throw new Error(`Function ${mod || 'global'}!${symbol} not found`)
  const range = Process.findRangeByAddress(p)
  if (!range?.protection.includes('x')) throw new Error('Invalid symbol, expected a function but received a data pointer')
  const id = p.toString()
  if (hooked.has(id)) throw new Error(`There is already a listener on ${id}`)

  const lib = mod || Process.getModuleByAddress(p)!.name
  const listener = Interceptor.attach(p, {
    onEnter(args) {
      const time = now()
      const pretty = signature.args.map((type, i) => readable(type, args[i]))
      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).filter(e => e.name)
      
      this.backtrace = backtrace
      send({
        subject,
        event: 'call',
        args: pretty,
        lib,
        symbol,
        backtrace,
        time
      })
    },
    onLeave(retVal) {
      if (!signature.ret) return
      const time = now()
      const ret = readable(signature.ret, retVal)

      send({
        subject,
        event: 'return',
        lib,
        symbol,
        time,
        backtrace: this.backtrace,
        ret
      })
    }
  })

  hooked.set(id, listener)

  return listener
}

export function unhook(mod: string, symbol: string) {
  const library = Process.findModuleByName(mod)
  if (!library) throw new Error(`Module ${mod} is not loaded`)
  const p = library.findExportByName(symbol)
  const name = `${mod || ''}!${symbol}`
  if (!p) throw new Error(`${name} not found`)
  const id = p.toString()
  hooked.get(id)?.detach()
  if (!hooked.has(id)) console.warn(`${name} has not been hooked before`)
}

const swizzled = new Map<string, Map<string, InvocationListener>>()
export function swizzle(clazz: string, sel: string, traceResult = true) {
  if (swizzled.get(clazz)?.get(sel)) return // already hooked
  if (!ObjC.classes[clazz]) throw new Error(`Class ${clazz} not loaded`)
  if (!ObjC.classes[clazz][sel]) throw new Error(`method ${sel} not found in ${clazz}`)

  const method = ObjC.classes[clazz][sel]
  let onLeave: ((retval: InvocationReturnValue) => void) | undefined = undefined
  if (traceResult) {
    onLeave = (retVal) => {
      const time = now()
      let ret = retVal.toString()
      try {
        // this is buggy
        ret = new ObjC.Object(retVal).toString()
      } catch (ignored) {
        //
      }
      send({
        subject,
        event: 'objc-return',
        clazz,
        sel,
        ret,
        time
      })
    }
  }

  const listener = Interceptor.attach(method.implementation, {
    onEnter(args) {
      const time = now()
      const readableArgs = []
      for (let i = 2; i < method.argumentTypes.length; i++) {
        if (method.argumentTypes[i] === 'pointer') {
          try {
            const obj = new ObjC.Object(args[i]).toString()
            readableArgs.push(obj)
          } catch (ex) {
            readableArgs.push(args[i])
          }
        } else {
          readableArgs.push(args[i])
        }
      }

      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).filter(e => e.name)

      send({
        subject,
        event: 'objc-call',
        backtrace,
        args: readableArgs,
        clazz,
        sel,
        time
      })
    },
    onLeave
  })

  if (!swizzled.has(clazz)) {
    swizzled.set(clazz, new Map([[sel, listener]]))
  } else {
    swizzled.get(clazz)!.set(sel, listener)
  }

  return listener
}

export function unswizzle(clazz: string, sel: string) {
  const listener = swizzled.get(clazz)?.get(sel)
  if (listener) listener.detach()
  swizzled.get(clazz)?.delete(sel)
}

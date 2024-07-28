interface Signature {
  args: string[];
  ret?: string;
}

const subject = 'hook'
const now = () => (new Date()).getTime()
const readable = (type: string, arg: NativePointer) => (type === 'char *' ? arg.readUtf8String() : arg)
const hooked = new Map<string, InvocationListener>()

export function hook(mod: string | null, symbol: string, signature: Signature) {
  const p = Module.findExportByName(mod, symbol)
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

export function unhook(mod: string | null, symbol: string) {
  const p = Module.findExportByName(mod, symbol)
  const name = `${mod || ''}!${symbol}`
  if (!p) throw new Error(`${name} not found`)
  const id = p.toString()
  hooked.get(id)?.detach()
  if (!hooked.has(id)) console.warn(`${name} has not been hooked before`)
}

interface NSMethodSignature extends ObjC.Object {
  numberOfArguments(): number;
  getArgumentTypeAtIndex_(index: number): string;
  methodReturnType(): string;
}

const swizzled = new Map<string, Map<string, InvocationListener>>()
export function swizzle(className: string, sel: string) {
  if (swizzled.get(className)?.get(sel)) return // already hooked

  const clazz = ObjC.classes[className]
  if (!clazz) throw new Error(`Class ${className} not loaded`)

  const method = clazz[sel]
  if (!method) throw new Error(`Method ${sel} not found in ${className}`)

  const listener = Interceptor.attach(method.implementation, {
    onEnter(args) {
      const self = new ObjC.Object(args[0])
      const signature = self.methodSignatureForSelector_(ObjC.selector(sel))
      const nargs = signature.numberOfArguments()
      const formattedArgs = []

      for (let i = 2; i < nargs; i++) {
        const arg = args[i]
        const t = signature.getArgumentTypeAtIndex_(i)
        const wrapped = t.toString().startsWith('@') ? new ObjC.Object(arg) : arg;
        formattedArgs.push(wrapped.toString());
      }

      const time = now()
      const backtrace = Thread.backtrace(this.context, Backtracer.ACCURATE)
        .map(DebugSymbol.fromAddress).filter(e => e.name)

      this.returnsObject = signature.methodReturnType().toString().startsWith('@')

      send({
        subject,
        event: 'objc-call',
        backtrace,
        args: formattedArgs,
        clazz: className,
        sel,
        time
      })
    },
    onLeave(retVal) {
      const time = now()
      const ret = this.returnsObject ? new ObjC.Object(retVal).toString() : retVal.toString()

      send({
        subject,
        event: 'objc-return',
        clazz: className,
        sel,
        ret,
        time
      })
    }
  })

  if (swizzled.has(className)) {
    swizzled.get(className)!.set(sel, listener)
  } else {
    swizzled.set(className, new Map([[sel, listener]]))
  }

  return listener
}

export function unswizzle(clazz: string, sel: string) {
  const listener = swizzled.get(clazz)?.get(sel)
  if (listener) listener.detach()
  swizzled.get(clazz)?.delete(sel)
}

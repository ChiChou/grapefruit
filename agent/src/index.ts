import ObjC from 'frida-objc-bridge'

import './ready.js'
import './polyfill.js'
// import './observers/http'

// import { init as enableLifeCycleHook } from './observers/lifecycle.js'

import { interfaces, invoke, register } from './rpc.js'
import modules from './modules/index.js'

function registerModules() {
  for (const [name, submodule] of Object.entries(modules)) {
    for (const [method, func] of Object.entries(submodule as {[key: string]: Function})) {
      if (method === 'default')
        register(func, name)
      else
        register(func, [name, func.name].join('/'))
    }
  }
}

setImmediate(registerModules)
// setImmediate(enableLifeCycleHook)

// disable autolock
ObjC.schedule(ObjC.mainQueue, () => {
  try {
    ObjC.classes.UIApplication.sharedApplication().setIdleTimerDisabled_(ptr(1))
  } finally {

  }
})

Process.setExceptionHandler((detail) => {
  console.error('Exception report: ')
  console.error(JSON.stringify(detail, null, 4))
  send({
    subject: 'exception',
    detail
  })
  const { context } = detail
  const pc = Instruction.parse(context.pc)
  console.warn(DebugSymbol.fromAddress(context.pc))
  console.error(pc.toString())
  console.error(Instruction.parse(pc.next).toString())  
  console.error('Backtrace')
  console.error(
    Thread.backtrace(context, Backtracer.ACCURATE)
      .map(addr => DebugSymbol.fromAddress(addr).toString()).join('\n'))
  
  return false
})

Interceptor.attach(Module.findGlobalExportByName('objc_exception_throw')!, {
  onEnter(args) {
    console.error('Objective-C exception:', new ObjC.Object(args[0]))
  }
})

rpc.exports = {
  interfaces,
  invoke,
}

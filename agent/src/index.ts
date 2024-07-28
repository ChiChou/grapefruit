import { init as enableLifeCycleHook } from './observers/lifecycle.js'
import { interfaces, invoke } from './registry.js'

import './modules/checksec.js'
import './modules/classdump.js'
import './modules/cookies.js'
import './modules/fs.js'
import './modules/info.js'
import './modules/jsc.js'
import './modules/keychain.js'
import './modules/sqlite.js'
import './modules/symbol.js'
import './modules/syslog.js'
import './modules/ui.js'
import './modules/url.js'
import './modules/userdefaults.js'
import './modules/webview.js'

setImmediate(enableLifeCycleHook)

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

Interceptor.attach(Module.findExportByName(null, 'objc_exception_throw')!, {
  onEnter(args) {
    console.error('Objective-C exception:', new ObjC.Object(args[0]))
  }
})

rpc.exports = {
  invoke,
  interfaces,
}

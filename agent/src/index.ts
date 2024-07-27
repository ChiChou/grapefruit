import { init as enableLifeCycleHook } from './observers/lifecycle.js'

import * as cookies from './modules/cookies.js'
import * as jsc from './modules/jsc.js'
import { cp, ls, rm, attr, plist as readPlist, text as readText, writeText, expand } from './modules/fs.js'

import { entitlements, flags } from './modules/checksec.js'
import { basics, plist, userDefaults } from './modules/info.js'
import { dismissHighlight, highlight, dump as dumpUI } from './modules/ui.js'
import { open as opendb, query, close as closedb, dump as dumpdb, tables } from './modules/sqlite.js'

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
  // info
  basics,
  plist,
  userDefaults,

  // checksec
  entitlements,
  flags,

  // cookies
  allCookies: cookies.list,
  clearCookies: cookies.clear,
  setCookie: cookies.write,
  deleteCookie: cookies.remove,

  // jsc
  jsContexts: jsc.list,
  jscDump: jsc.dump,
  runjs: jsc.run,

  highlight,
  dismissHighlight,
  dumpUI,

  // sqlite
  opendb,
  query,
  closedb,
  dumpdb,

  // fs
  expand,
  ls,
  cp,
  rm,  
  attr,
  readPlist,
  readText,
  writeText,
}
import './ready'
import './polyfill'
// import './observers/http'

import { init as appLifeCycleHook, dispose as disableAppLifeCycleHook } from './observers/lifecycle'

import { interfaces, invoke, register } from './rpc'
import modules from './modules/index'

rpc.exports = {
  interfaces,
  invoke,
}

function registerModules() {
  const destructors = new Set<Function>()
  for (const [name, submodule] of Object.entries(modules)) {
    for (const [method, func] of Object.entries(submodule as {[key: string]: Function})) {
      if (method === 'default')
        register(func, name)
      else if (method === 'dispose')
        destructors.add(func)
      else
        register(func, [name, func.name].join('/'))
    }
  }

  destructors.add(disableAppLifeCycleHook)

  // fixme: destructor hook doesn't work at all
  // script destroyed before receiving this message
  recv('dispose', () => {
    for (const cb of destructors) {
      try {
        cb()
      } finally {

      }
    }
  })  
}

registerModules()
appLifeCycleHook()

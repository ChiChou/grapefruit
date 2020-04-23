import './ready'
import './polyfill'
// import './observers/http'

import { init as appLifeCycleHook } from './observers/lifecycle'

import { interfaces, invoke, register } from './rpc'
import modules from './modules/index'

rpc.exports = {
  interfaces,
  invoke,
}

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

registerModules()
appLifeCycleHook()

recv('dispose', () => {
  // todo: dispose
})

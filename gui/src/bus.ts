import Vue from 'vue'

const bus = new Vue()

function install(V: typeof Vue) {
  V.prototype.$bus = bus
}

export default { install, bus }

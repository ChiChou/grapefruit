import Vue from 'vue'

const bus = new Vue()

function install(V: typeof Vue): void {
  V.prototype.$bus = bus
}

export default { install, bus }

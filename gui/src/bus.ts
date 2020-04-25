import Vue from 'vue'

const bus = new Vue()

function install(V: typeof Vue, opt: object) {
  V.prototype.$bus = bus
}

export default { install }

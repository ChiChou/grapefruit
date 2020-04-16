import Vue from 'vue'
import VueRouter from 'vue-router'

import Workspace from '../views/Workspace.vue'
import Welcome from '../views/Welcome.vue'

import DeviceView from '../views/Device.vue'
import Storage from '../views/panels/Storage.vue'
import Files from '../views/panels/Files.vue'
import Runtime from '../views/panels/Runtime.vue'
import General from '../views/panels/General.vue'

Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'Welcome',
    component: Welcome,
    children: [{
      path: 'apps/:device',
      component: DeviceView,
      name: 'Apps'
    }]
  }, {
    path: '/workspace/:device/:bundle',
    name: 'Workspace',
    component: Workspace,
    children: [{
      path: 'storage',
      name: 'Storage',
      component: Storage
    }, {
      path: 'files',
      name: 'Files',
      component: Files
    }, {
      path: 'runtime',
      name: 'Runtime',
      component: Runtime
    }, {
      path: 'general',
      name: 'General',
      component: General
    }]
  }
]

const router = new VueRouter({
  mode: 'history',
  linkActiveClass: 'is-active',
  base: process.env.BASE_URL,
  routes
})

export default router

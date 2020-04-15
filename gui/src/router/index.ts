import Vue from 'vue'
import VueRouter from 'vue-router'

import Workspace from '../views/Workspace.vue'
import Welcome from '../views/Welcome.vue'

import DeviceView from '../views/Device.vue'

Vue.use(VueRouter)

const routes = [
  {
    path: '/',
    name: 'Welcome',
    component: Welcome,
    children: [{
      path: 'apps/:device',
      component: DeviceView,
      name: 'apps'
    }]
  }, {
    path: '/workspace/:device/:bundle',
    name: 'Workspace',
    component: Workspace
  }
]

const router = new VueRouter({
  mode: 'history',
  linkActiveClass: 'is-active',
  base: process.env.BASE_URL,
  routes
})

export default router

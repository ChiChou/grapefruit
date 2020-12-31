import Vue from 'vue'
import VueRouter from 'vue-router'

import Workspace from '../views/Workspace.vue'
import Welcome from '../views/Welcome.vue'

import DeviceView from '../views/Device.vue'

import Files from '../views/panels/Files.vue'
import ClassDump from '../views/panels/ClassDump.vue'
import General from '../views/panels/General.vue'
import Hook from '../views/panels/Hook.vue'
import REPL from '../views/panels/REPL.vue'
import Modules from '../views/panels/Modules.vue'
import ApiResolver from '../views/panels/ApiResolver.vue'
import WebViews from '../views/panels/WebViews.vue'

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
      path: 'files',
      name: 'Files',
      component: Files
    }, {
      path: 'classes',
      name: 'Classes',
      component: ClassDump
    }, {
      path: 'modules',
      name: 'Modules',
      component: Modules
    }, {
      path: 'general',
      name: 'General',
      component: General
    }, {
      path: 'hook',
      name: 'Hook',
      component: Hook
    }, {
      path: 'resolver',
      name: 'Api Resolver',
      component: ApiResolver
    }, {
      path: 'webviews',
      name: 'WebViews',
      component: WebViews
    }, {
      path: 'repl',
      name: 'REPL',
      component: REPL
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

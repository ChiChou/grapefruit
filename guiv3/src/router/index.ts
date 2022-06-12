import { createRouter, createWebHistory } from 'vue-router'

import SelectTarget from '@/components/SelectTarget.vue'
import DeviceView from '@/views/DeviceView.vue'
import WorkspaceView from '@/views/WorkspaceView.vue'
import EmptyDeviceView from '@/views/EmptyDeviceView.vue'

import GeneralTab from '@/views/tabs/GeneralTab.vue'
import REPLTab from '@/views/tabs/REPLTab.vue'
import JSCTab from '@/views/tabs/JSCTab.vue'
import ModulesTab from '@/views/tabs/ModulesTab.vue'
import FinderTab from '@/views/tabs/FinderTab.vue'
import ClassesTab from '@/views/tabs/ClassesTab.vue'

const routes = [
  {
    path: '/',
    name: 'Welcome',
    component: SelectTarget,
    children: [{
      path: '',
      component: EmptyDeviceView,
    }, {
      path: 'apps/:device',
      component: DeviceView,
      name: 'Apps'
    }]
  },
  {
    path: '/workspace/:device/:bundle',
    name: 'Workspace',
    component: WorkspaceView,
    children: [
      {
        path: 'general',
        name: 'General',
        component: GeneralTab
      },
      {
        path: 'classes',
        name: 'Classes',
        component: ClassesTab
      },
      {
        path: 'modules',
        name: 'Modules',
        component: ModulesTab
      },
      {
        path: 'repl',
        name: 'REPL',
        component: REPLTab
      },
      {
        path: 'finder',
        name: 'Finder',
        component: FinderTab
      },
      {
        path: 'jsc',
        name: 'JavaScriptCore',
        component: JSCTab
      },
    ]
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  linkActiveClass: 'is-active',
  routes
})

export default router

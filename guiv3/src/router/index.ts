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
        components: {
          SideBar: GeneralTab
        }
      },
      {
        path: 'classes',
        name: 'Classes',
        components: {
          SideBar: ClassesTab
        }
      },
      {
        path: 'modules',
        name: 'Modules',
        components: {
          SideBar: ModulesTab
        }
      },
      {
        path: 'repl',
        name: 'REPL',
        components: {
          SideBar: REPLTab
        }
      },
      {
        path: 'finder',
        name: 'Finder',
        components: {
          SideBar: FinderTab
        }
      },
      {
        path: 'jsc',
        name: 'JavaScriptCore',
        components: {
          SideBar: JSCTab
        }
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

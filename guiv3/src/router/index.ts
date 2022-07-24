import { createRouter, createWebHistory } from 'vue-router'

import SelectTarget from '@/components/SelectTarget.vue'
import DeviceView from '@/views/DeviceView.vue'
import WorkspaceView from '@/views/WorkspaceView.vue'
import EmptyDeviceView from '@/views/EmptyDeviceView.vue'

import GetStarted from '@/views/pages/GetStarted.vue'

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
        path: '',
        component: GetStarted,
        name: 'GetStarted'
      }
    ]
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  linkActiveClass: 'is-active',
  routes
})

export default router

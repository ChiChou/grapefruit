import { createRouter, createWebHistory } from 'vue-router'

import SelectTarget from '@/components/SelectTarget.vue'
import DeviceView from '@/views/DeviceView.vue'
import SimulatorView from '@/views/SimulatorView.vue'
import WorkspaceView from '@/views/WorkspaceView.vue'
import EmptyDeviceView from '@/views/EmptyDeviceView.vue'

const routes = [
  {
    path: '/',
    name: 'select',
    component: SelectTarget,
    children: [{
      path: '',
      component: EmptyDeviceView,
    }, {
      path: 'apps/:device',
      component: DeviceView,
      name: 'apps'
    }, {
      path: 'simulator/:sim/apps',
      component: SimulatorView,
      name: 'simapps'
    }]
  },
  {
    path: '/workspace/:device/:bundle',
    name: 'workspace',
    component: WorkspaceView
  },
  {
    path: '/simulator/workspace/:sim/:bundle',
    name: 'simulator',
    component: WorkspaceView
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  linkActiveClass: 'is-active',
  routes
})

export default router

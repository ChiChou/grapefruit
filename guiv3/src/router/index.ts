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
      name: 'welcome',
    }, {
      path: 'device/:udid/apps',
      component: DeviceView,
      name: 'apps'
    }, {
      path: 'simulator/:udid/apps',
      component: DeviceView,
      name: 'simapps'
    }]
  },
  {
    path: '/workspace/device/:udid/:bundle',
    name: 'app',
    component: WorkspaceView
  },
  {
    path: '/workspace/simulator/:udid/:bundle',
    name: 'simapp',
    component: WorkspaceView
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  linkActiveClass: 'is-active',
  routes
})

export default router

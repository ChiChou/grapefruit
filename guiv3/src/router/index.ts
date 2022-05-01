import { createRouter, createWebHistory } from 'vue-router'

import SelectTarget from '@/components/SelectTarget.vue'
import DeviceView from '@/views/DeviceView.vue'
import WorkspaceView from '@/views/WorkspaceView.vue'

import GeneralTab from '@/views/tabs/GeneralTab.vue'

const routes = [
  {
    path: '/',
    name: 'Welcome',
    component: SelectTarget,
    children: [{
      path: 'apps/:device',
      component: DeviceView,
      name: 'Apps'
    }]
  },
  {
    path: '/workspace/:device/:bundle',
    name: 'Workspace',
    component: WorkspaceView,
    children: [{
      path: 'general',
      name: 'General',
      component: GeneralTab
    }]
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  linkActiveClass: 'is-active',
  routes
})

export default router

import { createRouter, createWebHistory } from 'vue-router'

import SelectTarget from '@/components/SelectTarget.vue'
import DeviceView from '@/views/DeviceView.vue'
import WorkspaceView from '@/views/WorkspaceView.vue'
import EmptyDeviceView from '@/views/EmptyDeviceView.vue'

import GetStarted from '@/views/pages/GetStarted.vue'
import BasicInfo from '@/views/pages/BasicInfo.vue'

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
    }]
  },
  {
    path: '/workspace/:device/:bundle',
    name: 'workspace',
    component: WorkspaceView,
    children: [
      {
        path: '',
        component: GetStarted,
        name: 'get-started'
      }, 
      {
        name: 'basic',
        component: BasicInfo,
        path: 'basic'
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

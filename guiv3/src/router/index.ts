import { createRouter, createWebHistory } from 'vue-router'

import SelectTarget from '@/components/SelectTarget.vue'
import DeviceView from '@/views/DeviceView.vue'
import WorkspaceView from '@/views/WorkspaceView.vue'
import EmptyDeviceView from '@/views/EmptyDeviceView.vue'

const routes = [
  {
    path: '/',
    name: 'select',
    component: SelectTarget,
    meta: {
      title: 'Select Target'
    },
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
    path: '/workspace/:mode(device|simulator)/:udid/:bundle',
    name: 'workspace',
    component: WorkspaceView
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  linkActiveClass: 'is-active',
  routes
})

router.beforeEach((to, from, next) => {
  const { title } = to.meta
  document.title = typeof title === 'string' ? title : 'Grapefruit'
  next();
})

export default router

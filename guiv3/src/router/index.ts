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
    component: WorkspaceView,
    redirect: { name: 'general' },
    children: [{
      path: 'general',
      component: () => import('@/views/panels/GeneralTab.vue'),
      name: 'general',
    }, {
      path: 'modules',
      component: () => import('@/views/panels/ModulesTab.vue'),
      name: 'modules',
    }, {
      path: 'classes',
      component: () => import('@/views/panels/ClassesTab.vue'),
      name: 'classes',
    }, {
      path: 'finder',
      component: () => import('@/views/panels/FinderTab.vue'),
      name: 'finder',
      redirect: { name: 'finder-home' },
      children: [{
        path: 'docs',
        component: () => import('@/views/panels/FoldersTree.vue'),
        name: 'finder-home',
      }, {
        path: 'bundle',
        component: () => import('@/views/panels/FoldersTree.vue'),
        name: 'finder-app',
      }]
    }]
  }
]

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  linkActiveClass: 'is-active',
  routes
})

router.beforeEach((to, from, next) => {
  const { title } = to.meta
  if (typeof title === 'string' && title !== document.title) {
    document.title = title
  }
  next();
})

export default router

import Vue from 'vue'
import axios from 'axios'
import pane from 'vue-splitpane'
import VueVirtualScroller from 'vue-virtual-scroller'

import Buefy, { SnackbarProgrammatic as Snackbar } from 'buefy'
import 'buefy/dist/buefy.css'
import '../bulmaswatch/darkly/bulmaswatch.scss'
import '@mdi/font/css/materialdesignicons.css'

import 'vue-virtual-scroller/dist/vue-virtual-scroller.css'

import 'golden-layout/src/css/goldenlayout-base.css'
// import 'golden-layout/src/css/goldenlayout-dark-theme.css'
import './golden-layout-theme-dark.scss'

import * as VueMenu from '@hscmap/vue-menu'

import App from './App.vue'
import RPC from './wsrpc'
import Bus from './bus'
import router from './router'
import store from './store'

axios.defaults.baseURL = '/api'
axios.interceptors.response.use(response => response, error => {
  Snackbar.open({
    type: 'is-warning',
    queue: false,
    message: error.response.data,
    actionText: 'Dismiss'
  })
  return Promise.reject(error)
})

Vue.config.productionTip = false
Vue.component('split-pane', pane)
Vue.use(Buefy)
Vue.use(VueVirtualScroller)
Vue.use(VueMenu)
Vue.use(RPC, { router })
Vue.use(Bus)

new Vue({
  router,
  store,
  render: h => h(App)
}).$mount('#app')

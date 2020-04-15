import Vue from 'vue'

import pane from 'vue-splitpane'
import Buefy from 'buefy'
import 'buefy/dist/buefy.css'
import '../bulmaswatch/darkly/bulmaswatch.scss'
import '@mdi/font/css/materialdesignicons.css'

// eslint-disable-next-line
import vgl from 'vue-golden-layout'
import 'golden-layout/src/css/goldenlayout-dark-theme.css'

import * as VueMenu from '@hscmap/vue-menu'

import App from './App.vue'
import router from './router'
import store from './store'

Vue.config.productionTip = false
Vue.component('split-pane', pane)
Vue.use(Buefy)
Vue.use(vgl)
Vue.use(VueMenu)

new Vue({
  router,
  store,
  render: h => h(App)
}).$mount('#app')

import { createApp } from 'vue'
import App from './App.vue'
import router from './router'

import naive from './plugins/naive'

createApp(App).use(naive).use(router).mount('#app');

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useLoadingBar } from 'naive-ui'
import { io } from 'socket.io-client'

import axios from '@/plugins/axios'

import DarkMode from '@/components/DarkMode.vue'

interface Device {
  name: string;
  removable: boolean;
  id: string;
}

const version = ref('N/A')
const node = ref('N/A')
const loading = ref(false)
const devices = ref([] as Device[])

onMounted(() => {
  const socket = io('/devices', { transports: ['websocket'] })
  socket.on('deviceChanged', refresh)
  refresh()
})

const loadingBar = useLoadingBar()

function refresh() {
  loadingBar.start()
  loading.value = true
  axios.get('/devices')
    .then(({ data }) => {
      devices.value = data.list
      version.value = data.version
      node.value = data.node
      loadingBar.finish()
    })
    .catch(e => {
      loadingBar.error()
    })
    .finally(() => {
      loading.value = false
    })
}

</script>

<template>
  <main>
    <aside>
      <header>
        <a href="/" class="logo">
          <img src="../assets/logo.svg" alt="Grapefruit" width="160" id="logo" />
        </a>

      <dark-mode />
      </header>

      <p>
        NodeJS {{ node }} <br />
        node-frida {{ version }}
      </p>

      <n-divider />

      <nav class="devices">
        <router-link v-for="(dev, i) in devices" :to="{ name: 'apps', params: { device: dev.id } }">
          {{ dev.name }}</router-link>

        <span v-if="devices.length === 0">No iPhone detected</span>
      </nav>

      <n-divider />

      <nav>
        <a target="_blank" href="https://github.com/chichou/grapefruit">GitHub</a>
        <a target="_blank" href="https://discord.com/invite/pwutZNx">Discord</a>
      </nav>

      <n-divider />

    </aside>

    <div class="apps">
      <router-view></router-view>
    </div>
  </main>
</template>

<style lang="scss" scoped>
main {
  display: flex;
  flex-direction: row;
}

aside {
  width: 280px;
  padding: 40px;


  nav a {
    text-decoration: none;
    display: block;
    padding: 0.5rem 1rem;
  }

  nav.devices a {
    border-radius: 4px;
    transition: background-color 0.2s ease-in-out;
    margin-top: 2px;
    margin-bottom: 2px;

    &.is-active {
      color: var(--highlight-text);
      background-color: var(--highlight-background);
    }

    &:hover {
      color: var(--highlight-text);
      background: var(--hover-background);
    }
  }
}

.apps {
  flex: 1;
}
</style>

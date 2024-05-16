<script setup lang="ts">
import { ref, onMounted, onBeforeUnmount } from 'vue'
import { useLoadingBar } from 'naive-ui'
import { io } from 'socket.io-client'

import * as api from '@/plugins/api'

import DarkMode from '@/components/DarkMode.vue'

interface DeviceInfo {
  name: string;
  removable: boolean;
  id: string;
}

interface SimulatorInfo {
  deviceTypeIdentifier: string;
  state: SimulatorState;
  name: string;
  udid: string;
}

interface DevicesResponse {
  list: DeviceInfo[];
  version: string;
  node: string;
}

type SimulatorState = 'Shutdown' | 'Booted'

const version = ref('N/A')
const node = ref('N/A')
const loading = ref(false)
const devices = ref([] as DeviceInfo[])
const simulators = ref([] as SimulatorInfo[])

const socket = io('/devices', { transports: ['websocket'] })

onMounted(() => {
  socket.on('deviceChanged', refresh)
  refresh()
  // reloadSimulators()
})

onBeforeUnmount(() => socket.close())

const loadingBar = useLoadingBar()

function reloadSimulators() {
  api.get<SimulatorInfo[]>('/simulators').then(data => { simulators.value = data })
}

function refresh() {
  loadingBar.start()
  loading.value = true
  api.get<DevicesResponse>('/devices')
    .then( data => {
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
      <div class="fixed">
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

        <p class="label">Physical Devices</p>

        <nav class="devices">
          <router-link v-for="(dev, i) in devices" :to="{ name: 'apps', params: { udid: dev.id } }">
            {{ dev.name }}</router-link>

          <span v-if="devices.length === 0">No iPhone detected</span>
        </nav>

        <!-- frida is currently broken for attaching Simulator apps -->
        <!-- https://github.com/frida/frida/issues/2763 -->
        <!-- <n-divider />
        
        <p class="label">Simulators</p>

        <nav class="simulators">
          <router-link v-for="(sim, i) in simulators" :to="{ name: 'simapps', params: { udid: sim.udid } }">
            {{ sim.name }}</router-link>

          <span v-if="simulators.length === 0">No simulator running</span>
        </nav> -->

        <n-divider />

        <nav>
          <a target="_blank" href="https://github.com/chichou/grapefruit">GitHub</a>
          <a target="_blank" href="https://discord.com/invite/pwutZNx">Discord</a>
        </nav>

        <n-divider />
      </div>
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
  --n-side-width: 280px;

  width: var(--n-side-width);
  padding: 40px;

  > div.fixed {
    position: fixed;
    width: var(--n-side-width);
  }

  p.label {
    font-size: .75rem;
    opacity: .75;
  }

  nav a {
    text-decoration: none;
    display: block;
    padding: 0.5rem 1rem;
  }

  nav.devices, nav.simulators {
    a {
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
}

.apps {
  flex: 1;
  margin-right: 1rem;
}
</style>

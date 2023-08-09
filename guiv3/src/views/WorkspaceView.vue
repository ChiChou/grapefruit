<script setup lang="ts">
import { ref, onMounted, provide, onBeforeUnmount, ComponentPublicInstance, onUnmounted } from 'vue'

import { Splitpanes, Pane } from 'splitpanes'
import { useRoute, useRouter } from 'vue-router'
import { io } from 'socket.io-client'
import 'splitpanes/dist/splitpanes.css'
import '@/skin/splitpane.scss'

import SidePanel from './SidePanel.vue'
import StatusBar from './StatusBar.vue'
import DarkMode from '@/components/DarkMode.vue'
import Layout from '@/components/Layout.vue'

import { useRPC } from '@/wsrpc'
import { SESSION_DETACH, RPC, STATUS, WS, ACTIVE_SIDEBAR, SPACE_WIDTH, SPACE_HEIGHT, TAB_EMITTER } from '@/types'
import { manager } from '@/plugins/tab'

import * as regulation from '@/regulation'

const isSimulator = () => route.name === 'simapp'
const isDevice = () => route.name === 'app'

const SIDEBAR_WIDTH_KEY = 'sidebar-width'
const sideWidth = ref(getInt(SIDEBAR_WIDTH_KEY, 20))
const TERM_HEIGHT_KEY = 'term-height'
const termHeight = ref(getInt(TERM_HEIGHT_KEY, 30))
const el = ref<ComponentPublicInstance>()

function getInt(key: string, def: number) {
  const str = localStorage.getItem(key)
  if (str) {
    const val = parseFloat(str)
    if (!Number.isNaN(val)) {
      return val
    }
  }
  return def
}

type SizeData = {
  min: number
  max: number
  size: number
}

function saveLayout() {
  localStorage.setItem(SIDEBAR_WIDTH_KEY, sideWidth.value.toString())
  localStorage.setItem(TERM_HEIGHT_KEY, termHeight.value.toString())
}

function resizing(data: SizeData[]) {
  if (data.length) {
    sideWidth.value = data[0].size
  }

  if (el && el.value) {
    const div = el.value.$el as HTMLDivElement
    spaceWidth.value = div.clientWidth
    spaceHeight.value = div.clientHeight
  }
}

const route = useRoute()
const router = useRouter()
const { udid, bundle } = route.params

// todo: GUI
if (typeof bundle !== 'string') {
  throw new Error('invalid bundle id')
}

document.title = `${bundle} - Grapefruit`

if (typeof udid !== 'string') {
  throw new Error('invalid device udid')
}

if (regulation.check(bundle)) {
  throw new Error('According to local regulations, Grapefruit is not working on current app')
}

const socket = io('/session', { query: { mode: isSimulator() ? 'simulator' : 'device', udid, bundle }, transports: ['websocket'] })
const status = ref('connecting')

provide(WS, socket)
provide(RPC, useRPC(socket))
provide(STATUS, status)

const spaceWidth = ref(0)
const spaceHeight = ref(0)

provide(SPACE_WIDTH, spaceWidth)
provide(SPACE_HEIGHT, spaceHeight)

const onWindowResize = () => resizing([])

onMounted(() => {
  window.addEventListener('resize', onWindowResize)
  requestAnimationFrame(onWindowResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', onWindowResize)
})

function onDisconnect() {
  // todo: Dialog
  status.value = 'disconnected'
}

socket
  .on('ready', () => {
    status.value = 'connected'
  })
  .on('detached', onDisconnect)
  .on('destroyed', onDisconnect)
  .on('exception', (msg) => {

  })

function detach() {
  if (isSimulator()) {
    const { sim } = route.params
    router.push({
      name: 'simapps',
      params: { sim }
    })
  } else if (isDevice()) {
    const { device } = route.params
    router.push({
      name: 'apps',
      params: { device }
    })
  }
}

provide(SESSION_DETACH, detach)

onBeforeUnmount(() => socket.close())

const activeSidebar = ref(0)
provide(ACTIVE_SIDEBAR, activeSidebar)

provide(TAB_EMITTER, manager)

function rick() {
  window.open('https://www.youtube.com/watch?v=dQw4w9WgXcQ', '_blank')
}

</script>

<template>
  <div class="pane-full">
    <header class="workspace-header">
      <a href="#" class="logo" @dblclick="rick">
        <img src="../assets/grapefruit.svg" alt="Grapefruit" width="24" height="24" id="logo" />
      </a>
      <dark-mode />
    </header>
    <main class="workspace-main-container">
      <splitpanes class="split-pane-container" @resize="resizing($event)" @resized="saveLayout">
      <pane min-size="10" :size="sideWidth" max-size="80">
        <SidePanel></SidePanel>
      </pane>
      <pane>
        <layout ref="el" style="width: 100%; height: 100%"></layout>
      </pane>
    </splitpanes>
    </main>
    <StatusBar />
  </div>
</template>

<style lang="scss">
:root {
  --n-workspace-header-height: 40px;
  --workspace-header-background: #2b2b2b;
}

[data-theme="dark"] {
  --workspace-header-background: #1f1f1f;
}

.workspace-header {
  display: flex;
  align-items: center;
  justify-content: space-between;
  height: var(--n-workspace-header-height);
  background-color: var(--workspace-header-background);

  > a {
    height: 24px;
    display: block;
    width: 24px;
    padding: 8px 20px;
  }
}

.workspace-main-container {
  flex: 1;
}

.pane-full {
  height: 100vh;
  width: 100vw;
  display: flex;
  overflow: hidden;
  flex-direction: column;
}
</style>
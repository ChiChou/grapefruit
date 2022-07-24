<script setup lang="ts">
import { ref, onMounted, provide, onBeforeUnmount } from 'vue'

import { Splitpanes, Pane } from 'splitpanes'
import { useRoute, useRouter } from 'vue-router'
import 'splitpanes/dist/splitpanes.css'
import '@/skin/splitpane.scss'

import SidePanel from './SidePanel.vue'
import StatusBar from './StatusBar.vue'
import * as regulation from '@/regulation'
import { useRPC } from '@/wsrpc'
import { io } from 'socket.io-client'
import { SESSION_DETACH, RPC, STATUS, WS, ACTIVE_SIDEBAR } from '@/types'

const SIDEBAR_WIDTH_KEY = 'sidebar-width'
const sideWidth = ref(20)
const TERM_HEIGHT_KEY = 'term-height'
const termHeight = ref(30)

function restoreLayout() {
  // remember the layout
  const width = localStorage.getItem(SIDEBAR_WIDTH_KEY)
  if (width) {
    const val = parseFloat(width)
    if (!Number.isNaN(val)) {
      sideWidth.value = val
    }
  }

  const height = localStorage.getItem(TERM_HEIGHT_KEY)
  if (height) {
    const val = parseFloat(height)
    if (!Number.isNaN(val)) {
      termHeight.value = val
    }
  }
}

type SizeData = {
  min: number
  max: number
  size: number
}

function saveLayout(data: SizeData[]) {
  localStorage.setItem(SIDEBAR_WIDTH_KEY, sideWidth.value.toString())
  localStorage.setItem(TERM_HEIGHT_KEY, termHeight.value.toString())
}

onMounted(() => {
  restoreLayout()
})

const route = useRoute()
const router = useRouter()
const { device, bundle } = route.params
if (typeof device !== 'string' || typeof bundle !== 'string') {
  throw new Error('invalid params')
}

if (regulation.check(bundle)) {
  // todo: GUI
  throw new Error('According to local regulations, Grapefruit is not working on current app')
}

const socket = io('/session', { query: { device, bundle }, transports: ['websocket'] })
const status = ref('connecting')

provide(WS, socket)
provide(RPC, useRPC(socket))
provide(STATUS, status)

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

function detach() {
  const { device } = route.params
  router.push({
    name: 'Apps',
    params: { device }
  })
}

provide(SESSION_DETACH, detach)

onBeforeUnmount(() => socket.close())

const activeSidebar = ref(0)
provide(ACTIVE_SIDEBAR, activeSidebar)

</script>

<template>
  <div class="pane-full">
    <splitpanes style="flex: 1" @resize="sideWidth = $event[0].size" @resized="saveLayout">
      <pane min-size="10" :size="sideWidth" max-size="80">
        <SidePanel></SidePanel>
      </pane>
      <pane>
        <router-view></router-view>
      </pane>
    </splitpanes>
    <StatusBar />
  </div>
</template>

<style lang="scss">
.pane-full {
  height: 100vh;
  width: 100vw;
  display: flex;
  overflow: hidden;
  flex-direction: column;
}
</style>
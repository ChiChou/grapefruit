<script setup lang="ts">
import { ref, onMounted, provide, onBeforeUnmount, ComponentPublicInstance, onUnmounted } from 'vue'

import { Splitpanes, Pane } from 'splitpanes'
import { useRoute, useRouter } from 'vue-router'
import 'splitpanes/dist/splitpanes.css'
import '@/skin/splitpane.scss'

import SidePanel from './SidePanel.vue'
import StatusBar from './StatusBar.vue'
import Layout from '@/components/Layout.vue'
import * as regulation from '@/regulation'
import { useRPC } from '@/wsrpc'
import { io } from 'socket.io-client'
import { SESSION_DETACH, RPC, STATUS, WS, ACTIVE_SIDEBAR, SPACE_WIDTH, SPACE_HEIGHT } from '@/types'

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
      console.log('val=', val)
      return val
    }
  }
  console.log('default=', def)
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

const onWindowResize = () => resizing([])

onMounted(() => {
  window.addEventListener('resize', onWindowResize)
  requestAnimationFrame(onWindowResize)
})

onUnmounted(() => {
  window.removeEventListener('resize', onWindowResize)
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

const spaceWidth = ref(0)
const spaceHeight = ref(0)

provide(SPACE_WIDTH, spaceWidth)
provide(SPACE_HEIGHT, spaceHeight)

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
    name: 'apps',
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
    <splitpanes class="split-pane-container" @resize="resizing($event)" @resized="saveLayout">
      <pane min-size="10" :size="sideWidth" max-size="80">
        <SidePanel></SidePanel>
      </pane>
      <pane>
        <layout ref="el" style="width: 100%; height: 100%"></layout>
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

.splitpanes--vertical .splitpanes__pane {
  transition: none !important;
}

.splitpanes__splitter {
  transition: 0.2s ease-in-out background-color !important;
}
</style>
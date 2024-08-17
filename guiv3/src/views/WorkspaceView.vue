<script setup lang="ts">
import { ref, onMounted, provide, onBeforeUnmount, ComponentPublicInstance, onUnmounted } from 'vue'

import { useRoute, useRouter } from 'vue-router'
import { io } from 'socket.io-client'

import SidePanel from './SidePanel.vue'
import StatusBar from './StatusBar.vue'
import Layout from '@/components/Layout.vue'

import { useRPC } from '@/wsrpc'
import { SESSION_DETACH, RPC, STATUS, WS, SPACE_WIDTH, SPACE_HEIGHT, TAB_EMITTER } from '@/types'
import { manager } from '@/plugins/tab'

import * as regulation from '@/regulation'

const SPLIT_SIZE_KEY = 'split-size'
const splitterSize = ref(getNumber(SPLIT_SIZE_KEY, .2))
const el = ref<ComponentPublicInstance>()

function getNumber(key: string, def: number) {
  const str = localStorage.getItem(key)
  if (str) {
    const val = parseFloat(str)
    if (!Number.isNaN(val)) {
      return val
    }
  }
  debugger
  return def
}

function saveLayout() {
  localStorage.setItem(SPLIT_SIZE_KEY, splitterSize.value.toString())
}

function resizing(size: number) {  
  splitterSize.value = size as number

  if (el && el.value) {
    const div = el.value.$el as HTMLDivElement
    spaceWidth.value = div.clientWidth
    spaceHeight.value = div.clientHeight
  }
}

const route = useRoute()
const router = useRouter()
const { udid, bundle } = route.params
const mode = route.params.mode as string

const isSimulator = () => mode === 'simulator'
const isDevice = () => mode === 'device'

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

const socket = io('/session', { query: { mode, udid, bundle }, transports: ['websocket'] })
const status = ref('connecting')

provide(WS, socket)
provide(RPC, useRPC(socket))
provide(STATUS, status)

const spaceWidth = ref(0)
const spaceHeight = ref(0)

provide(SPACE_WIDTH, spaceWidth)
provide(SPACE_HEIGHT, spaceHeight)

const onWindowResize = () => resizing(splitterSize.value)

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

provide(TAB_EMITTER, manager)

</script>

<template>
  <div class="pane-full">    
    <main class="workspace-main-container">
      <n-split direction="horizontal" style="height: 100%" :min="'320px'" :max=".5" :size="splitterSize" @update-size="resizing" @drag-end="saveLayout()">
        <template #1>
          <SidePanel></SidePanel>
        </template>
        <template #2>
          <layout ref="el" style="width: 100%; height: 100%"></layout>
        </template>
      </n-split>
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
  min-height: 0;
}

.pane-full {
  height: 100vh;
  width: 100vw;
  display: flex;
  overflow: hidden;
  flex-direction: column;
}
</style>
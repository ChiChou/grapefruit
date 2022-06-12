<script setup lang="ts">
import { ref, onMounted } from 'vue'

import { Splitpanes, Pane } from 'splitpanes'
import 'splitpanes/dist/splitpanes.css'
import '@/skin/splitpane.scss'

import SidePanel from './SidePanel.vue'
import StatusBar from './StatusBar.vue'

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

</script>

<template>
  <div class="pane-full">
    <splitpanes style="flex: 1" @resize="sideWidth = $event[0].size" @resized="saveLayout">
      <pane min-size="20" :size="sideWidth" max-size="80">
        <SidePanel></SidePanel>
      </pane>
      <pane>
        <splitpanes horizontal @resize="termHeight = $event[1].size" @resized="saveLayout">
          <pane></pane>
          <pane :size="termHeight" max-size="100">{{ termHeight }}</pane>
        </splitpanes>
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
  flex-direction: column;
}
</style>
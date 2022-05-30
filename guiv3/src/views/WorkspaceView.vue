<script setup lang="ts">
import { ref, onMounted } from 'vue'

import { Splitpanes, Pane } from 'splitpanes'
import 'splitpanes/dist/splitpanes.css'
import '@/skin/splitpane.scss'

import SidePanel from './SidePanel.vue'

onMounted(() => {

})


</script>

<template>
  <splitpanes style="flex: 1" class="pane-full">
    <pane min-size="20" size="20">
      <SidePanel></SidePanel>
    </pane>
    <pane>
      <splitpanes horizontal>
        <pane></pane>
        <pane size="30"></pane>
      </splitpanes>
    </pane>
  </splitpanes>
</template>

<style lang="scss">
.pane-full {
  height: 100vh;
  width: 100vw;
}
</style>
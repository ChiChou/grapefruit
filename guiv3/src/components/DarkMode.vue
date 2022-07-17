<template>
  <n-space>
    <n-switch @update:value="switchDarkMode" v-model:value="darkModeStore.dark">
      <template #icon>
        <n-icon :component="LightModeOutlined" />
      </template>
      <template #checked>
        Dark
      </template>
      <template #unchecked>
        Light
      </template>
    </n-switch>
  </n-space>
</template>

<script lang="ts" setup>
import { LightModeOutlined } from '@vicons/material'
import { useDarkModeStore } from '@/stores/darkmode'

const darkModeStore = useDarkModeStore()
function switchDarkMode(val: boolean) {
  darkModeStore.off(val)
}
</script>
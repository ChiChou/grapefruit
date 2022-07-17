<template>
  <n-space>
    <n-switch @update:value="switchDarkMode" v-model:value="isDark">
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
import { inject } from 'vue'
import { LightModeOutlined } from '@vicons/material'
import { DARK } from '@/types'

const isDark = inject(DARK)

function switchDarkMode(val: boolean) {
  isDark!.value = val
}
</script>
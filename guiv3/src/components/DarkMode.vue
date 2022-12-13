<template>
  <n-space>
    <n-switch @update:value="switchDarkMode" v-model:value="isDark">
      <template #icon>
        <n-icon :component="icon" />
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
import { computed, inject } from 'vue'
import { LightModeOutlined, DarkModeOutlined } from '@vicons/material'
import { DARK } from '@/types'

const isDark = inject(DARK)

const icon = computed(() => isDark?.value ? DarkModeOutlined : LightModeOutlined)

function switchDarkMode(val: boolean) {
  isDark!.value = val
}
</script>
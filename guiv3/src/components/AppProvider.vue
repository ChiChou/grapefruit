<template>
  <n-config-provider :theme="theme" :class="{ dark: theme === darkTheme}">
    <n-loading-bar-provider>
      <n-message-provider>
        <n-dialog-provider>
          <slot></slot>
        </n-dialog-provider>
      </n-message-provider>
    </n-loading-bar-provider>
    <n-global-style />
  </n-config-provider>
</template>

<script setup lang="ts">
import { onMounted, provide, ref, watch } from 'vue'
import { darkTheme } from 'naive-ui'
import { BuiltInGlobalTheme } from 'naive-ui/lib/themes/interface'
import { DARK } from '@/types'

const PRESIST_KEY = 'theme'
const MEDIA_QUERY = '(prefers-color-scheme: dark)'

const theme = ref(null as BuiltInGlobalTheme | null)
const isDark = ref(init())

window
  .matchMedia(MEDIA_QUERY)
  .addEventListener('change', (e) => {
    isDark.value = e.matches
  })

function apply(dark: boolean) {
  const { dataset } = document.documentElement
  if (dark) {
    theme.value = darkTheme
    dataset.theme = 'dark'
  } else {
    theme.value = null
    dataset.theme = 'light'
  }

  localStorage.setItem(PRESIST_KEY, dataset.theme)
}

function init() {
  const v = localStorage.getItem(PRESIST_KEY)
  if (v === 'light') {
    return false
  } else if (v === 'dark') {
    return true
  }
  return window.matchMedia(MEDIA_QUERY).matches
}

provide(DARK, isDark)
watch(isDark, (val) => apply(val))
onMounted(() => apply(isDark.value))

</script>

<style lang="scss">
:root {
  --highlight-background: #f7f7f7;
  --highlight-color: #000;
  
  --n-link-text-color: rgb(51, 54, 57);
  --n-link-text-color-hover: #36ad6a;
  --n-link-text-color-active: #18a058;
  --n-link-text-color-pressed: #0c7a43;

  --hover-background: #f7f7f7;

  a {
    color: var(--n-link-text-color);
    &:hover, &:focus {
      color: var(--n-link-text-color-hover);
    }

    &:active {
      color: var(--n-link-text-color-pressed);
    }
  }
}

[data-theme="dark"] {
  --highlight-background: #282828;
  --highlight-text: #fff;

  --n-link-text-color: rgba(255, 255, 255, 0.82);
  --n-link-text-color-hover: #7fe7c4;
  --n-link-text-color-active: #63e2b7;
  --n-link-text-color-pressed: #5acea7;

  --hover-background: #1abc9c;
}
</style>
<template>
  <n-config-provider :theme="theme" :class="{ dark: theme === darkTheme}" @theme="onThemeChanged">
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
import { onMounted, ref } from 'vue';
import { darkTheme } from 'naive-ui'
import { BuiltInGlobalTheme } from 'naive-ui/lib/themes/interface';

const theme = ref(null as BuiltInGlobalTheme | null)

function lightsOff(isDark: boolean) {
  if (isDark) {
    theme.value = darkTheme
    document.documentElement.dataset.theme = 'dark'
  } else {
    theme.value = null
    document.documentElement.dataset.theme = undefined
  }
}

window
  .matchMedia('(prefers-color-scheme: dark)')
  .addEventListener('change', (e) => {
    lightsOff(e.matches)
  })

function onThemeChanged(isDark: boolean) {
  lightsOff(isDark)
  if (isDark) localStorage.setItem('theme', 'dark')
}

onMounted(() => {
  const pref = localStorage.getItem('theme')
  if (pref === null) {
    // use system theme
    lightsOff(window.matchMedia('(prefers-color-scheme: dark)').matches)
  } else {
    lightsOff(pref === 'dark')
  }
})

</script>

<style lang="scss">
:root {
  --highlight-background: #f7f7f7;
  --highlight-color: #000;
}

:root[data-theme="dark"] {
  --highlight-background: #1abc9c;
  --highlight-text: #fff;
}
</style>
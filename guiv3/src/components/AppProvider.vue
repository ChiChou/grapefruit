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
import { onMounted, provide, ref } from 'vue';
import { darkTheme } from 'naive-ui'
import { BuiltInGlobalTheme } from 'naive-ui/lib/themes/interface';
import { useDarkModeStore } from '@/stores/darkmode';

const theme = ref(null as BuiltInGlobalTheme | null)
const darkModeStore = useDarkModeStore()

window
  .matchMedia('(prefers-color-scheme: dark)')
  .addEventListener('change', (e) => {
    darkModeStore.off(e.matches)
  })

darkModeStore.$subscribe((mutation, state) => apply(state.dark))

function apply(dark: boolean) {
  if (dark) {
    theme.value = darkTheme
    document.documentElement.dataset.theme = 'dark'
  } else {
    theme.value = null
    document.documentElement.dataset.theme = undefined
  }  
}

onMounted(() => apply(darkModeStore.dark))

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
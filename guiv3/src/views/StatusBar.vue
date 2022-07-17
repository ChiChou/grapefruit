<template>
  <footer class="status-bar-global">
    <div>Ready</div>
    <div><dark-mode /></div>
  </footer>
</template>

<style lang="scss">
:root {
  --n-status-bar-height: 24px;
  --status-background: rgb(0, 122, 204)
}

.status-bar-global {
  height: var(--n-status-bar-height);
  background-color: var(--status-background);
  color: #fff;
  display: flex;

  > div {
    margin-left: 1rem;
    margin-right: 1rem;
  }
}
</style>

<script lang="ts" setup>
import DarkMode from '@/components/DarkMode.vue'
</script>
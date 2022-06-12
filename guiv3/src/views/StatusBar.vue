<template>
  <footer class="status-bar-global">
    Ready
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
}
</style>
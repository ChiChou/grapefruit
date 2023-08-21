<script lang="ts" setup>
import { Folder28Filled, AppFolder24Filled } from '@vicons/fluent'
</script>

<template>
  <main>
    <header>
      <router-link :to="{name: 'finder-home'}">
        <n-icon><Folder28Filled /></n-icon>Home
      </router-link>
      <router-link :to="{name: 'finder-app'}">
        <n-icon><AppFolder24Filled /></n-icon>App
      </router-link>
    </header>
    <router-view></router-view>
  </main>
</template>

<style lang="scss" scoped>

main {
  height: 100%;
  display: flex;
  flex-direction: column;
}

header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  background-color: var(--highlight-background);
}

header > a {
  align-items: center;
  flex: 1;
  text-align: center;
  text-decoration: none;
  padding: 0.5rem 1rem;
  color: var(--text-color);
  transition: color 0.2s ease-in-out;
  border-bottom: 2px solid transparent;

  .n-icon {
    margin-right: 0.5rem;
  }

  &:hover {
    color: var(--highlight-text);
  }

  &.is-active {
    color: var(--highlight-text);
    border-bottom-color: aquamarine; // todo: light mode
  }
}
</style>
<script setup lang="ts">
import MainMenu from '@/components/MainMenu.vue'
import { Component as Comp, h, ref } from 'vue'
import {
  AutoAwesomeMosaicSharp,
  FolderSharp,
  ExploreRound,
  ViewModuleSharp,
  TerminalSharp,
} from '@vicons/material'

import {
  Braces
} from '@vicons/tabler'

import router from '@/router'

const icons: {[key: string]: Comp } = {
  'general': AutoAwesomeMosaicSharp,
  'classes': Braces,
  'modules': ViewModuleSharp,
  'repl': TerminalSharp,
  'finder': FolderSharp,
  'jsc': ExploreRound,
}

const routes = router.getRoutes()
const parent = routes.find(r => r.name === 'Workspace')
const tabs = parent?.children.map(r => {
  return {
    name: r.name,
    icon: icons[r.path],
    label: r.name,
    path: r.path
  }
})

</script>

<template>
  <div class="side-navigator">
    <nav class="side-nav">
      <MainMenu></MainMenu>

      <n-popover trigger="hover" v-for="(tab) in tabs" placement="right">
        <template #trigger>
          <router-link :to="tab.path">
            <n-icon :component="tab.icon" :size="32"></n-icon>
          </router-link>
        </template>
        <span>{{ tab.label }}</span>
      </n-popover>
    </nav>
    <aside class="sidebar">
      <router-view></router-view>
    </aside>
  </div>
</template>

<style lang="scss">
:root {
  --sidebar-background: #eee;
  --sidebar-nav-background: #fefefe;
  --nav-active: #303030;
}

[data-theme="dark"] {
  --sidebar-background: #181818;
  --sidebar-nav-background: #212121;
  --nav-active: #bcbcbc;
}

.side-navigator {
  display: flex;
  flex: 1;
  height: 100%;

  nav.side-nav {
    width: 72px;
    background: var(--sidebar-nav-background);

    .n-radio-group__splitor {
      display: none;
    }

    a {
      display: flex;
      cursor: pointer;
      width: 68px;
      height: 60px;
      align-items: center;
      justify-content: center;

      border-left: 2px solid transparent;
      border-right: 2px solid transparent;

      &.is-active {
        border-left-color: var(--nav-active);
      }
    }
  }

  aside.sidebar {
    background-color: var(--sidebar-background);
    flex: 1;
  }
}
</style>
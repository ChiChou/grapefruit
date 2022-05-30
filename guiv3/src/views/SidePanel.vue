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


import REPLTab from './tabs/REPLTab.vue'
import JSCTab from './tabs/JSCTab.vue'
import ModulesTab from './tabs/ModulesTab.vue'
import GeneralTab from './tabs/GeneralTab.vue'
import FinderTab from './tabs/FinderTab.vue'
import ClassesTab from './tabs/ClassesTab.vue'

type TabOption = {
  label: string;
  icon: Comp;
  page: Comp;
}

const tabs: TabOption[] = [
  {
    label: 'General',
    icon: AutoAwesomeMosaicSharp,
    page: GeneralTab,
  },
  {
    label: 'Classes',
    icon: Braces,
    page: ClassesTab,
  },
  {
    label: 'Modules',
    icon: ViewModuleSharp,
    page: ModulesTab,
  },
  {
    label: 'Terminal',
    icon: TerminalSharp,
    page: REPLTab,
  },
  {
    label: 'Finder',
    icon: FolderSharp,
    page: FinderTab,
  },
  {
    label: 'JavaScriptCore',
    icon: ExploreRound,
    page: JSCTab,
  }
]

const index = ref(0)

</script>

<template>
  <div class="side-navigator">
    <nav class="side-nav">
      <MainMenu></MainMenu>

      <n-popover trigger="hover" v-for="(tab, i) in tabs" placement="right">
        <template #trigger>
          <a @click="index = i" :class="{ active: index === i }">
            <n-icon :component="tab.icon" :size="32"></n-icon>
          </a>
        </template>
        <span>{{ tab.label }}</span>
      </n-popover>
    </nav>
    <aside class="sidebar">
      <component :is="tabs[index].page"></component>
    </aside>
  </div>
</template>

<style lang="scss">
.side-navigator {
  display: flex;
  flex: 1;
  height: 100%;

  nav.side-nav {
    width: 60px;
    background: #212121;

    .n-radio-group__splitor {
      display: none;
    }

    a {
      display: flex;
      cursor: pointer;
      width: 64x;
      height: 60px;
      align-items: center;
      justify-content: center;

      border-left: 2px solid transparent;

      &.active {
        border-left-color: var(--highlight-background);
      }
    }
  }

  aside.sidebar {
    background-color: #181818;
    flex: 1;
  }
}
</style>
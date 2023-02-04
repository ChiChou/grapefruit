<script setup lang="ts">
import MainMenu from '@/components/MainMenu.vue'

import REPLTab from './panels/REPLTab.vue'
import JSCTab from './panels/JSCTab.vue'
import ModulesTab from './panels/ModulesTab.vue'
import GeneralTab from './panels/GeneralTab.vue'
import FinderTab from './panels/FinderTab.vue'
import ClassesTab from './panels/ClassesTab.vue'

import { Component as Comp, inject, onMounted } from 'vue'
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
import { ACTIVE_SIDEBAR } from '@/types'

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

const KEY = 'ACTIVE_TAB'
const index = inject(ACTIVE_SIDEBAR)!

onMounted(() => {
  const i = parseInt(sessionStorage.getItem(KEY) || '0')
  index.value = i
})

function select(i: number) {
  index.value = i
  sessionStorage.setItem(KEY, i.toString())
}

</script>

<template>
  <div class="side-navigator">
    <nav class="side-nav">
      <MainMenu></MainMenu>

      <n-popover trigger="hover" v-for="(tab, i) in tabs" placement="right">
        <template #trigger>
          <a @click="select(i)" :class="{ 'is-active': index === i }">
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
:root {
  --sidebar-background: #f3f3f3;
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



aside.menu {
  padding: 1rem;

  .menu-label {
    margin: 0;
    font-size: 0.75rem;
  }

  ul {
    padding-left: 0.5rem;
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;

    li {
      .n-icon {
        margin-right: 0.5rem;
      }

      a {
        text-decoration: none;
        display: block;
        padding: 0.25rem;
        border-radius: 2px;

        &:hover {
          background: rgba(0, 0, 0, 0.1);
        }
      }

      display: block;
      font-size: 1rem;
      list-style: none;
    }
  }
}
</style>
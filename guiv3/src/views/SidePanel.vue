<script setup lang="ts">
import MainMenu from '@/components/MainMenu.vue'

import REPLTab from './panels/REPLTab.vue'
import JSCTab from './panels/JSCTab.vue'
import ModulesTab from './panels/ModulesTab.vue'
import GeneralTab from './panels/GeneralTab.vue'
import FinderTab from './panels/FinderTab.vue'
import ClassesTab from './panels/ClassesTab.vue'

import { Component as Comp, Ref, inject, onMounted, provide, ref } from 'vue'
import {
  HomeSharp,
  FolderSharp,
  ExploreRound,
  ViewModuleSharp,
  TerminalSharp,
} from '@vicons/material'

import {
  Braces
} from '@vicons/tabler'
import { SIDE_PANEL_HEIGHT } from '@/types'

type TabOption = {
  label: string;
  icon: Comp;
  page: Comp;
  to: string;
}

const tabs: TabOption[] = [
  {
    label: 'General',
    icon: HomeSharp,
    page: GeneralTab,
    to: 'general',
  },
  {
    label: 'Modules',
    icon: ViewModuleSharp,
    page: ModulesTab,
    to: 'modules',
  },
  {
    label: 'Classes',
    icon: Braces,
    page: ClassesTab,
    to: 'classes',
  },
  {
    label: 'Finder',
    icon: FolderSharp,
    page: FinderTab,
    to: 'finder',
  },
  // {
  //   label: 'Terminal',
  //   icon: TerminalSharp,
  //   page: REPLTab,
  //   to: 'terminal',
  // },
  // {
  //   label: 'JavaScriptCore',
  //   icon: ExploreRound,
  //   page: JSCTab,
  //   to: 'jsc',
  // }
]

const height = ref(0)
provide(SIDE_PANEL_HEIGHT, height)

const el = ref<HTMLElement | null>(null)
function updateSize() {
  const { value } = el
  if (!value) return
  height.value = value.clientHeight
}

const resizeObserver = new ResizeObserver(updateSize)

onMounted(() => {
  resizeObserver.observe(el.value!)
  updateSize()
})

function rick() {
  window.open('https://www.youtube.com/watch?v=dQw4w9WgXcQ', '_blank')
}

</script>

<template>
  <div class="side-navigator">
    <nav class="side-nav">
      <a href="#" class="logo" @dblclick="rick">
        <img src="../assets/grapefruit.svg" alt="Grapefruit" width="24" height="24" id="logo" />
      </a>

      <!-- <MainMenu></MainMenu> -->

      <n-popover trigger="hover" v-for="(tab, i) in tabs" placement="right">
        <template #trigger>
          <router-link :to="{ name: tab.to }">
            <n-icon :component="tab.icon" :size="24"></n-icon>
          </router-link>
        </template>
        <span>{{ tab.label }}</span>
      </n-popover>
    </nav>
    <aside class="side" ref="el">
      <router-view></router-view>
    </aside>
  </div>
</template>

<style lang="scss">
:root {
  --side-background: #f3f3f3;
  --side-nav-background: #fefefe;
  --nav-active: #303030;
}

[data-theme="dark"] {
  --side-background: #181818;
  --side-nav-background: #212121;
  --nav-active: #bcbcbc;
}

.side-navigator {
  display: flex;
  flex: 1;
  height: 100%;

  nav.side-nav {
    background: var(--side-nav-background);

    .n-radio-group__splitor {
      display: none;
    }

    a {
      display: flex;
      cursor: pointer;
      margin-top: 2px;
      margin-bottom: 2px;
      width: 56px;
      height: 56px;
      align-items: center;
      justify-content: center;

      border-left: 4px solid transparent;
      border-right: 4px solid transparent;

      &.is-active {
        border-left-color: var(--nav-active);
      }
    }
  }

  aside.side {
    background-color: var(--side-background);
    flex: 1;
    min-width: 0;
    min-height: 0;
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
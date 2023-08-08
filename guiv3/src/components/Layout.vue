<template>
  <div ref="element" style="width: 100%; height: 100%">
    <link :href="css" rel="stylesheet" />
    <teleport v-for="{ id, type, element, state, tabId } in componentInstances" :key="id" :to="element">
      <component :is="type" :state="state" :tabId="tabId"></component>
    </teleport>
  </div>
</template>

<script lang="ts">
import { LayoutConfig, RootItemConfig } from "golden-layout"
import { defineComponent, inject, shallowRef, computed, watch, ref, onUnmounted, provide } from "vue"
import { DARK, SPACE_WIDTH, SPACE_HEIGHT, SET_TAB_TITLE } from "@/types"
import { useGoldenLayout } from "@/plugins/golden-layout"

import "golden-layout/dist/css/goldenlayout-base.css"

import lightThemeUrl from "golden-layout/dist/css/themes/goldenlayout-light-theme.css?url"
import darkThemeUrl from "golden-layout/dist/css/themes/goldenlayout-dark-theme.css?url"

import BasicInfo from '@/views/pages/BasicInfo.vue'
import GetStarted from '@/views/pages/GetStarted.vue'
import { manager as tabManager } from "@/plugins/tab-manager"

const components = { GetStarted, BasicInfo }

const KEY_LAYOUT = 'LAYOUT_SETTING'

export default defineComponent({
  components,
  setup() {
    interface ComponentInstance {
      id: number;
      tabId: string;
      type: string;
      element: HTMLElement;
      state: any;
    }

    let instanceId = 0
    const componentTypes = new Set(Object.keys(components))
    const componentInstances = shallowRef<ComponentInstance[]>([])
    const spaceWidth = inject(SPACE_WIDTH, ref(0))
    const spaceHeight = inject(SPACE_HEIGHT, ref(0))
    const isDark = inject(DARK)
    const css = computed(() => isDark?.value ? darkThemeUrl : lightThemeUrl)

    const createComponent = (type: string, tabId: string, element: HTMLElement, state?: any) => {
      if (!componentTypes.has(type)) {
        throw new Error(`Component not found: '${type}'`)
      }
      ++instanceId
      componentInstances.value = componentInstances.value.concat({
        id: instanceId,
        tabId,
        type,
        element,
        state,
      })
    }

    const destroyComponent = (toBeRemoved: HTMLElement) => {
      componentInstances.value = componentInstances.value.filter(
        ({ element }) => element !== toBeRemoved
      )
    }

    let root: RootItemConfig = {
      type: "column",
      content: [
        {
          type: "component",
          componentType: "GetStarted",
          title: 'Get Started'
        },
      ],
    }

    const val = localStorage.getItem(KEY_LAYOUT)
    if (val) {
      let savedRoot
      try {
        savedRoot = LayoutConfig.fromResolved(JSON.parse(val)).root
      } catch(e) {
        console.error(e)
      }

      if (savedRoot) {
        root = savedRoot as RootItemConfig
      }
    }

    const { element, layout } = useGoldenLayout(createComponent, destroyComponent, {
      root,
      // do not load following settings from localStorage
      dimensions: {
        headerHeight: 32,        
      },
      settings: {
        showPopoutIcon: false,
        showMaximiseIcon: false,
      }
    })

    provide(SET_TAB_TITLE, (id: string, title: string) => {
      layout.value?.findFirstComponentItemById(id)?.setTitle(title)
    })

    watch(spaceWidth, (width) => {
      layout.value?.setSize(width, spaceHeight.value)
    })

    watch(spaceHeight, (height) => {
      layout.value?.setSize(spaceWidth.value, height)
    })

    onUnmounted(() => tabManager.unload())

    return { element, componentInstances, css }
  },
})
</script>

<style lang="scss">
.lm_header .lm_controls{
  top: 4px;
}

.lm_header .lm_tab {
  font-size: 16px !important;
  height: 26px;
}

.lm_header .lm_tab .lm_close_tab {
  top: 8px !important;
}

.lm_content {
  overflow: auto;
}
</style>
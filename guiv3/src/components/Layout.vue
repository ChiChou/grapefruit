<template>
  <div ref="element" style="width: 100%; height: 100%">
    <link :href="css" rel="stylesheet" />
    <teleport v-for="{ id, type, element } in componentInstances" :key="id" :to="element">
      <component :is="type"></component>
    </teleport>
  </div>
</template>

<script lang="ts">
import { LayoutConfig } from "golden-layout"
import { defineComponent, inject, shallowRef, computed, watch, ref } from "vue"
import { DARK, SPACE_WIDTH, SPACE_HEIGHT, REGISTER_TAB_HANDLER } from "@/types"
import { useGoldenLayout } from "@/plugins/golden-layout"

import "golden-layout/dist/css/goldenlayout-base.css"

import lightThemeUrl from "golden-layout/dist/css/themes/goldenlayout-light-theme.css?url"
import darkThemeUrl from "golden-layout/dist/css/themes/goldenlayout-dark-theme.css?url"

import BasicInfo from '@/views/pages/BasicInfo.vue'
import GetStarted from '@/views/pages/GetStarted.vue'

const components = { GetStarted, BasicInfo }

const KEY_LAYOUT = 'LAYOUT_SETTING'

export default defineComponent({
  components,
  setup() {
    interface ComponentInstance {
      id: number;
      type: string;
      element: HTMLElement;
    }

    let instanceId = 0
    const componentTypes = new Set(Object.keys(components))
    const componentInstances = shallowRef<ComponentInstance[]>([])
    const isDark = inject(DARK)
    const spaceWidth = inject(SPACE_WIDTH, ref(0))
    const spaceHeight = inject(SPACE_HEIGHT, ref(0))
    const css = computed(() => isDark?.value ? darkThemeUrl : lightThemeUrl)

    const createComponent = (type: string, element: HTMLElement) => {
      if (!componentTypes.has(type)) {
        throw new Error(`Component not found: '${type}'`)
      }
      ++instanceId
      componentInstances.value = componentInstances.value.concat({
        id: instanceId,
        type,
        element,
      })
    }

    const destroyComponent = (toBeRemoved: HTMLElement) => {
      componentInstances.value = componentInstances.value.filter(
        ({ element }) => element !== toBeRemoved
      )
    }

    const { element, layout } = useGoldenLayout(createComponent, destroyComponent, {
      root: {
        type: "column",
        content: [
          {
            type: "component",
            componentType: "GetStarted",
            title: 'Get Started'
          },
        ],
      },
      dimensions: {
        headerHeight: 32,        
      },
      settings: {
        showPopoutIcon: false,
        showMaximiseIcon: false,
      }
    })

    const register = inject(REGISTER_TAB_HANDLER)!

    watch(layout, (l) => {
      if (!l) return

      const val = localStorage.getItem(KEY_LAYOUT)
      if (val) {
        try {
          l.loadLayout(LayoutConfig.fromResolved(JSON.parse(val)))
        } catch(_) {
          console.error(_)
        }
      }

      l.on('stateChanged', () => 
        localStorage.setItem(KEY_LAYOUT, JSON.stringify(l.saveLayout())))

      register((componentType: string, title: string, state: any, createNew?: boolean) => {
        if (!createNew) {
          const tab = l.findFirstComponentItemById(componentType)
          if (tab) {
            tab.parentItem.setActiveComponentItem(tab, true, true)
          } else {
            l.addItem({
              id: componentType,
              title,
              type: 'component',
              componentType
            })
          }
        } else {
          l.addComponent(componentType, state, title)
        }
      })
    })

    watch(spaceWidth, (width) => {
      layout.value?.setSize(width, spaceHeight.value)
    })

    watch(spaceHeight, (height) => {
      layout.value?.setSize(spaceWidth.value, height)
    })

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
</style>
<template>
  <div ref="element" style="width: 100%; height: 100%">
    <link :href="css" rel="stylesheet" />
    <teleport v-for="{ id, type, element } in componentInstances" :key="id" :to="element">
      <component :is="type"></component>
    </teleport>
  </div>
</template>

<script lang="ts">
import { useGoldenLayout } from "@/plugins/golden-layout"
import { defineComponent, h, inject, shallowRef, computed, watch, ref } from "vue"
import { DARK, SPACE_WIDTH, SPACE_HEIGHT } from "@/types"

import "golden-layout/dist/css/goldenlayout-base.css"

import lightThemeUrl from "golden-layout/dist/css/themes/goldenlayout-light-theme.css?url"
import darkThemeUrl from "golden-layout/dist/css/themes/goldenlayout-dark-theme.css?url"

const Test = defineComponent({ render: () => h('span', 'It works!') });

const components = { Test, /* other components */ };


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
            componentType: "Test",
          },
          {
            type: "component",
            componentType: "Test",
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
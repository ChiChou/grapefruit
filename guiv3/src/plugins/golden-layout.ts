import { ComponentContainer, GoldenLayout, LayoutConfig, RootItemConfig } from 'golden-layout'
import { onMounted, ref, shallowRef } from 'vue'

import { manager as tabManager, TabState } from './tab'

export const isClient = typeof window !== 'undefined'
export const isDocumentReady = () => isClient && document.readyState === 'complete' && document.body != null

const KEY_LAYOUT = 'LAYOUT_SETTING'

export function useDocumentReady(func: () => void) {
  onMounted(() => {
    if (isDocumentReady()) func()
    else
      document.addEventListener('readystatechange', () => isDocumentReady() && func(), {
        passive: true
      })
  })
}

function useSavedLayout(defaultRoot: RootItemConfig) {
  let root = defaultRoot;

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

  return {
    root,
    // do not load following settings from localStorage
    dimensions: {
      headerHeight: 32,        
    },
    settings: {
      showPopoutIcon: false,
      showMaximiseIcon: false,
    }
  }
}

export function useGoldenLayout(
  createComponent: (type: string, tabId: string, container: HTMLElement, state: TabState) => ComponentContainer.Component,
  destroyComponent: (container: HTMLElement) => void,
  defaultRoot: RootItemConfig
) {
  const element = shallowRef<HTMLElement | null>(null)
  const layout = shallowRef<GoldenLayout | null>(null)
  const initialized = ref(false)

  useDocumentReady(() => {
    if (element.value == null) throw new Error('Element must be set.')
    const goldenLayout = new GoldenLayout(element.value)

    goldenLayout.bindComponentEvent = (container, itemConfig) => {
      const { componentType, componentState } = itemConfig
      const state = componentState as TabState
      const { tabId } = state
      if (typeof componentType !== 'string') throw new Error('Invalid component type.')
      const component = createComponent(componentType, tabId, container.element, state)
      return {
        component,
        virtual: false,
      }
    }
    goldenLayout.unbindComponentEvent = container => {
      destroyComponent(container.element)
    }

    goldenLayout.on('stateChanged', () => {
      localStorage.setItem(KEY_LAYOUT, JSON.stringify(goldenLayout.saveLayout()))
    })

    goldenLayout.loadLayout(useSavedLayout(defaultRoot))

    // https://github.com/microsoft/TypeScript/issues/34933
    layout.value = goldenLayout as any

    initialized.value = true

    // listen for tab creation
    let counter = 0
    tabManager.listen((componentType: string, state: TabState, title?: string, createNew?: boolean) => {
      let tabId: string

      if (!createNew) {
        const tab = goldenLayout.findFirstComponentItemById(componentType)
        tabId = componentType
        if (tab) {
          tab.parentItem.setActiveComponentItem(tab, true, true)
          return
        }
      } else {
        tabId = `${componentType}${counter++}`
      }

      const componentState = Object.assign({ tabId }, state)
      goldenLayout.addItem({
        id: tabId,
        title,
        type: 'component',
        componentType,
        componentState
      })
    })
  })

  return { element, initialized, layout }
}

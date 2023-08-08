import { ComponentContainer, GoldenLayout, LayoutConfig } from 'golden-layout'
import { onMounted, ref, shallowRef } from 'vue'

import { manager as tabManager } from './tab'

export const isClient = typeof window !== 'undefined'
export const isDocumentReady = () => isClient && document.readyState === 'complete' && document.body != null

interface TabState {
  id: string,
  [key: string]: string
}

type StateOpt = {[key: string]: string} | null

export function useDocumentReady(func: () => void) {
  onMounted(() => {
    if (isDocumentReady()) func()
    else
      document.addEventListener('readystatechange', () => isDocumentReady() && func(), {
        passive: true
      })
  })
}

export function useGoldenLayout(
  createComponent: (type: string, tabId: string, container: HTMLElement, state?: any) => ComponentContainer.Component,
  destroyComponent: (container: HTMLElement) => void,
  config?: LayoutConfig
) {
  const element = shallowRef<HTMLElement | null>(null)
  const layout = shallowRef<GoldenLayout | null>(null)
  const initialized = ref(false)

  useDocumentReady(() => {
    if (element.value == null) throw new Error('Element must be set.')
    const goldenLayout = new GoldenLayout(element.value)

    goldenLayout.bindComponentEvent = (container, itemConfig) => {
      const { componentType, componentState } = itemConfig
      const tabId = (componentState as TabState).id
      if (typeof componentType !== 'string') throw new Error('Invalid component type.')
      const component = createComponent(componentType, tabId, container.element, componentState)
      return {
        component,
        virtual: false,
      }
    }
    goldenLayout.unbindComponentEvent = container => {
      destroyComponent(container.element)
    }

    if (config != null) goldenLayout.loadLayout(config)

    // https://github.com/microsoft/TypeScript/issues/34933
    layout.value = goldenLayout as any

    initialized.value = true

    // listen for tab creation
    let counter = 0
    tabManager.listen((componentType: string, state: StateOpt, title?: string, createNew?: boolean) => {
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

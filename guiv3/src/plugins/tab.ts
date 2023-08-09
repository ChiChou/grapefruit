import { inject, provide } from 'vue';
import { SET_TAB_TITLE, RPC, TAB_EMITTER } from '@/types';

type Listener = (componentType: string, state: any, title?: string, createNew?: boolean) => void

class TabManager {
  #listener: Listener | null = null
  #ready = false
  #pendingTabs: [string, string, any, boolean][] = []

  /**
   * singleton tab, should not support parameter
   * @param component name of the component
   * @param title initial title
   */
  go(component: string, title?: string) {
    this.#tab(component, {}, title, false)
  }

  create(component: string, state?: any, title?: string) {
    this.#tab(component, state, title, true)
  }

  #tab(component: string, state?: any, title?: string, newTab?: boolean) {
    const t = title || ''
    if (!this.#ready) {
      this.#pendingTabs.push([component, state, t, Boolean(newTab)])
    } else {
      this.#listener!(component, state, t, newTab)
    }
  }

  listen(fn: Listener) {
    if (this.#listener) {
      throw new Error(`Listener already defined. This method should only be used once.
        Did you forget to call unload()?`)
    }

    this.#pendingTabs.forEach(tuple => {
      const [component, state, title, newTab] = tuple
      this.#tab(component, title, state, newTab)
    })

    this.#listener = fn
    this.#ready = true
  }

  unload() {
    this.#listener = null
    this.#ready = false
    this.#pendingTabs = []
  }
}

export const manager = new TabManager()

export function useTabNavigator() {
  const go = manager.go.bind(manager)
  const create = manager.create.bind(manager)
  const listen = manager.listen.bind(manager)

  return {
    go,
    create,
    listen,
  }
}

export const tabProps = {
  tabId: String,
  id: Number,
  state: Object,
}

export function useTabCommons(tabId: string) {
  const rpc = inject(RPC)!;
  const updateTitle = inject(SET_TAB_TITLE)!;
  const entitle = (title: string) => {
    updateTitle(tabId, title)
  }

  return {
    rpc,
    entitle,
  }
}

// @ts-check
import { isSystemDark } from '@/utils'
import { defineStore, acceptHMRUpdate } from 'pinia'

const PRESIST_KEY = 'theme'
function init() {
  const v = localStorage.getItem(PRESIST_KEY)
  if (v === 'light') {
    return false
  } else if (v === 'dark') {
    return true
  }
  return isSystemDark()
}

function save() {
  // TODO: save to localStorage
}

export const useDarkModeStore = defineStore({
  id: 'darkmode',
  state: () => ({ dark: init() }),
  actions: {
    off(dark: boolean) {
      this.$patch({ dark })
      localStorage.setItem(PRESIST_KEY, dark ? 'dark' : 'light')
    }
  }
})

if (import.meta.hot) {
  import.meta.hot.accept(acceptHMRUpdate(useDarkModeStore, import.meta.hot))
}

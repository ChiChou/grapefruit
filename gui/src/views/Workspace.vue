<template>
  <div class="workspace">
    <MenuBar ref="menu" />
    <main>
      <SidePanel />

      <split-pane
        :min-percent="10"
        :default-percent="sideWidth"
        split="vertical"
        class="main-pane"
        @resize="sidebarResize"
      >
        <template slot="paneL">
          <div class="space space-sidebar">
            <keep-alive>
              <router-view></router-view>
            </keep-alive>
          </div>
        </template>
        <template slot="paneR">
          <split-pane split="horizontal" :default-percent="80" :min-percent="10" @resize="resize">
            <template slot="paneL">
              <div class="editor-container" ref="container"></div>
            </template>
            <template slot="paneR">
              <div class="space space-terminal">
                <Console ref="console" />
              </div>
            </template>
          </split-pane>
        </template>
      </split-pane>
    </main>

    <footer class="status">
      <b-dropdown aria-role="list" position="is-top-right">
        <div class="ws item" :class="loading" slot="trigger" role="button">
          <span v-if="loading === 'connected'">
            <b-icon icon="check-network" size="is-small" />Connected
          </span>
          <span v-else-if="loading === 'connecting'">
            <b-icon icon="loading" size="is-small" custom-class="mdi-spin" />Connecting
          </span>
          <span v-else>
            <b-icon icon="close-network-outline" size="is-small" />Connection Lost
          </span>
        </div>
        <b-dropdown-item aria-role="listitem" @click="$refs.menu.reload()">Reload</b-dropdown-item>
        <b-dropdown-item aria-role="listitem" @click="$refs.menu.detach()">Detach</b-dropdown-item>
        <b-dropdown-item aria-role="listitem" @click="$refs.menu.kill()">Stop</b-dropdown-item>
      </b-dropdown>
      <div class="app item">
        <b-icon icon="play" size="is-small" />
        {{ $route.params.bundle }}
      </div>
    </footer>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Watch } from 'vue-property-decorator'
import throttle from 'lodash.throttle'
// eslint-disable-next-line @typescript-eslint/no-unused-vars
import jQuery from 'jquery'
import colors, { StyleFunction } from 'ansi-colors'
import GoldenLayout, { Container, ContentItem, ComponentConfig } from 'golden-layout'

import MenuBar from './MenuBar.vue'
import SidePanel from '../views/SidePanel.vue'
import Console from '../components/Console.vue'
import Frame from '../views/tabs/Frame.vue'

import { Route } from 'vue-router'
import { Terminal } from 'xterm'

const SIDEBAR_WIDTH_KEY = 'sidebar-width'

type State = 'connected' | 'connecting' | 'disconnected'

// todo: utils
const uuid = () => 'id-' + Math.random().toString(36).slice(2)

@Component({
  components: {
    MenuBar,
    SidePanel,
    Console
  }
})
export default class Workspace extends Vue {
  resizeEvent: Function = () => {
    /* placeholder */
  }

  term?: Terminal
  loading: State = 'connecting'
  device?: string
  bundle?: string
  layout?: GoldenLayout
  sideWidth = 15

  mounted() {
    {
      // remember the layout
      const width = localStorage.getItem(SIDEBAR_WIDTH_KEY)
      if (width) {
        const val = parseFloat(width)
        if (!Number.isNaN(val)) {
          this.sideWidth = val
        }
      }
    }

    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    document.querySelector('html')!.classList.add('no-scroll')

    const { term } = this.$refs.console as Console
    this.term = term
    this.resizeEvent = throttle(this.updateSize, 100)
    this.term.writeln(colors.green('Welcome to Grapefruit!'))

    this.initLayout()
  }

  initLayout() {
    const defaultConfig = {
      settings: {
        showPopoutIcon: false,
        // showMaximiseIcon: false,
        selectionEnabled: true
      },
      // dimensions: {
      //   headerHeight: 30
      // },
      content: [{
        type: 'row',
        content: [{
          type: 'component',
          componentName: 'subview',
          componentState: { title: 'Basic Information', component: 'Info' }
        }, {
          type: 'component',
          componentName: 'subview',
          componentState: { title: 'Mitigations and Entitlements', component: 'CheckSec' }
        }]
      }]
    }

    let config = defaultConfig
    if (localStorage.getItem('bundle') === this.$route.params.bundle) {
      const item = localStorage.getItem('layout-state')
      if (item) {
        config = JSON.parse(item)
      }
    }

    const layout = this.layout = new GoldenLayout(config, this.$refs.container as HTMLDivElement)
    const tabsSingleton = new Map<string, ContentItem>()

    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    layout.registerComponent('subview', function(container: Container, state: any) {
      const { component, props, title } = state
      const propsData = { data: props, component, container }
      const FrameClass = Vue.extend(Frame)
      const v = new FrameClass({ propsData })
      v.$mount()
      container.setTitle(title)
      container.getElement().append(v.$el)
      container.on('resize', () => v.$emit('resize'))
      container.on('destroy', () => v.$destroy())
      tabsSingleton.set(component, container.parent)
    })

    layout.on('itemDestroyed', (item: ContentItem) => {
      if (!item.isComponent) return
      const { component } = (item.config as ComponentConfig).componentState
      if (tabsSingleton.has(component)) {
        tabsSingleton.delete(component)
      }
    })

    layout.on('stateChanged', () => {
      if (layout.isInitialised) {
        localStorage.setItem('layout-state', JSON.stringify(layout.toConfig()))
        localStorage.setItem('bundle', this.$route.params.bundle)
      }
    })

    try {
      layout.init()
    } catch (e) {
      console.warn('Failed to initialize layout. Reset')
      this.log('warn', 'Failed to initialize. Reset GUI')
      localStorage.clear()
      // localStorage.removeItem('layout-state')
      location.reload()
      return
    }

    const findMaximised = () => {
      const maximised = layout.root.getItemsByFilter((item: ContentItem) => item.isMaximised)
      if (maximised.length) return maximised.pop()
    }

    const createTab = (component: string, title: string, props?: object) => {
      const { root } = layout
      if (!root.contentItems.length) {
        root.addChild({
          type: 'stack',
          id: uuid(),
          content: []
        })
      }

      const max = findMaximised()
      if (max) max.toggleMaximise()

      const parent = root.getItemsByType('stack')[0]
      parent.select()
      parent.addChild({
        type: 'component',
        id: uuid(),
        componentName: 'subview',
        componentState: { title: title.substr(0, Math.min(title.length, 30)), component, props }
      })
      // parent.toggleMaximise()
    }

    this.$bus.$on('openTab', createTab)
    this.$bus.$on('switchTab', (component: string, title: string, props?: object) => {
      const max = findMaximised()
      if (max) max.toggleMaximise()

      const item = tabsSingleton.get(component)
      if (item) {
        const { parent } = item
        // if (parent !== max && !parent.isMaximised) parent.toggleMaximise()
        parent.setActiveContentItem(item)
      } else {
        createTab(component, title, props)
      }
    })
  }

  onKeyDown(ev: KeyboardEvent) {
    if (ev.key === 'w' && (ev.altKey || ev.ctrlKey)) {
      ev.preventDefault()
      ev.stopPropagation()
      this.closeTab()
    }
  }

  created() {
    window.addEventListener('resize', this.resize)
    window.addEventListener('unhandledrejection', (ev) => {
      this.log('error', 'unexpected error:', ev.reason)
    })
    window.addEventListener('keydown', this.onKeyDown)
  }

  beforeDestroy() {
    // eslint-disable-next-line @typescript-eslint/no-non-null-assertion
    document.querySelector('html')!.classList.remove('no-scroll')
    window.removeEventListener('resize', this.resize)
    window.removeEventListener('keydown', this.onKeyDown)
    if (this.layout) this.layout.destroy()
  }

  closeTab() {
    if (!this.layout?.selectedItem) return
    const { selectedItem } = this.layout
    const active = selectedItem.getActiveContentItem()
    if (selectedItem.isStack && active.isComponent) {
      try {
        active.remove()
      } catch (e) {
        console.error('failed to remove item', e, active)
      }
    }
  }

  @Watch('$route', { immediate: true })
  private navigate(route: Route) {
    const { device, bundle } = route.params

    if (device !== this.device || bundle !== this.bundle) {
      this.device = device
      this.bundle = bundle
      this.changed()
    }
  }

  log(level: string, ...args: string[]) {
    const { term } = this
    if (!term) {
      console.warn('terminal log', ...args)
      return
    }

    const color: {[key: string]: StyleFunction} = {
      info: colors.greenBright,
      error: colors.redBright,
      warn: colors.yellow,
      warning: colors.yellow
    }

    const renderer = color[level] || colors.whiteBright
    const ts = `[${new Date().toLocaleString()}]`
    const text = renderer([ts, ...args].join(' ').replace(/\n/g, '\r\n'))
    term.writeln(text)
  }

  changed() {
    this.loading = 'connecting'
    this.$ws
      .on('ready', () => {
        this.loading = 'connected'
      })
      .on('detached', this.disconnected)
      .on('destroyed', this.disconnected)
      .on('console', (level: string, text: string) => {
        this.log(level, text)
      })
  }

  disconnected(extra: string) {
    this.$buefy.snackbar.open({
      type: 'is-danger',
      position: 'is-top',
      actionText: 'Reload',
      // indefinite: true,
      duration: 10 * 1000,
      queue: false,
      message: `Session has been terminated (${extra || 'Unknown Reason'}). Please check your connection or, did App crashed?`,
      onAction: () => location.reload()
    })
    this.loading = 'disconnected'
  }

  updateSize() {
    (this.$refs.console as Console).resize()

    if (!this.layout) return
    const container = this.$refs.container as HTMLDivElement
    this.layout.updateSize(container.clientWidth, container.clientHeight)
  }

  resize() {
    this.resizeEvent()
  }

  sidebarResize(value: number) {
    this.resize()
    localStorage.setItem(SIDEBAR_WIDTH_KEY, value.toString())
  }
}
</script>

<style lang="scss">
.workspace {
  display: flex;
  flex-direction: column;
  height: 100vh;

  > main {
    flex: 1;
    display: flex;
    flex-direction: row;

    .action-bar {
      background: #282f2f;
    }

    .main-pane {
      flex: 1;
    }
  }
}

footer.status {
  font-size: 12px;
  background: #505050;
  display: flex;

  .item {
    display: inline-block;
    padding: 2px 4px;
    color: #fff;
  }

  .ws {
    cursor: pointer;

    &.connected {
      background: #068068;
    }

    &.connecting {
      background: #dfdf13;
      color: #111;
    }

    &.disconnected {
      background: #ea4335;
    }
  }
}

.side-nav {
  a {
    border-left: 2px solid transparent;
    display: block;
    padding: 1rem;
    color: #808080;

    &.is-active {
      border-left-color: #fff;
      color: #fff;
    }
  }
}

.space {
  height: 100%;
  width: 100%;

  &.space-sidebar {
    background: #343c3d;
  }

  &.space-terminal {
    background: #1e1e1e;
    .xterm {
      padding: 10px;
    }
  }
}

.editor-container {
  background: #2a2a2a;
  height: 100%;
  width: 100%;

  .windows {
    height: 100%;
    width: 100%;
  }
}

a.dropdown-item:hover, button.dropdown-item:hover {
  background: #00000031;
  color: #FFC107;
}
</style>

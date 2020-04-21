<template>
  <div class="workspace">
    <MenuBar ref="menu" />
    <main>
      <SidePanel />

      <split-pane
        :min-percent="10"
        :default-percent="15"
        split="vertical"
        class="main-pane"
        @resize="resize"
      >
        <template slot="paneL">
          <div class="space space-sidebar">
            <router-view class="classes">Place Holder</router-view>
          </div>
        </template>
        <template slot="paneR">
          <split-pane split="horizontal" :default-percent="80" :min-percent="20" @resize="resize">
            <template slot="paneL">
              <div class="editor-container">
                <!-- todo: golden-layout -->
              </div>
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
          <!-- todo: connect to disconnect -->
          <span v-if="loading === 'connected'">
            <b-icon icon="check-network" size="is-small"></b-icon>Connected
          </span>
          <span v-else-if="loading === 'connecting'">
            <b-icon icon="loading" size="is-small" custom-class="mdi-spin"></b-icon>Connecting
          </span>
          <span v-else>
            <b-icon icon="close-network-outline" size="is-small"></b-icon>Connection Lost
          </span>
        </div>
        <b-dropdown-item aria-role="listitem" @click="$refs.menu.detach()">Detach</b-dropdown-item>
        <b-dropdown-item aria-role="listitem" @click="$refs.menu.kill()">Stop</b-dropdown-item>
      </b-dropdown>
      <div class="app item">
        <b-icon icon="play" size="is-small"></b-icon>
        {{ $route.params.bundle }}
      </div>
    </footer>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Watch } from 'vue-property-decorator'
import debounce from 'debounce'
// import colors from 'ansi-colors'

import MenuBar from './MenuBar.vue'
import SidePanel from '../views/SidePanel.vue'
import Console from '../components/Console.vue'
import { Route } from 'vue-router'
import { Terminal } from 'xterm'

type State = 'connected' | 'connecting' | 'disconnected'

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

  mounted() {
    document.querySelector('html')!.classList.add('no-scroll')

    const { term } = this.$refs.console as Console
    this.term = term
    this.resizeEvent = debounce(this.updateSize, 100)
  created() {
    window.addEventListener('resize', this.resize)
  }
  beforeDestroy() {
    document.querySelector('html')!.classList.remove('no-scroll')
    window.removeEventListener('resize', this.resize)
    if (this.layout) this.layout.destroy()
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

  changed() {
    this.loading = 'connecting'

    // todo: vuex loading
    this.rpcReady().then(async() => {
      this.loading = 'connected'

      const decoder = new TextDecoder('utf-8')
      const buf = await this.$rpc.fs.text('/etc/passwd')

      const { term } = this
      if (!term) return
      term.writeln(decoder.decode(buf).replace(/\n/g, '\r\n'))

      const test = async(future: Promise<any>) =>
        term.writeln(
          JSON.stringify(await future, null, 4).replace(/\n/g, '\r\n')
        )
      test(this.$rpc.info.info())
      test(this.$rpc.checksec())
      test(this.$rpc.fs.ls('home'))
    })

    // todo: handle disconnection
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
}
</script>

<style lang="scss">
.workspace {
  display: flex;
  flex-direction: column;
  height: 100vh;
}

main {
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
  padding: 20px;
  height: 100%;
  width: 100%;

  &.space-sidebar {
    background: #343c3d;
  }

  &.space-terminal {
    background: #000;
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

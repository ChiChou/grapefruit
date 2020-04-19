<template>
  <div class="workspace">
    <MenuBar />
    <main>
      <SidePanel />

      <split-pane :min-percent="10" :default-percent="15" split="vertical" class="main-pane" @resize="resize">
        <template slot="paneL">
          <div class="space space-sidebar">
            <router-view class="classes">Place Holder</router-view>
          </div>
        </template>
        <template slot="paneR">
          <split-pane split="horizontal" :default-percent="80" :min-percent="20" @resize="resize">
            <template slot="paneL">
              <div class="editor-container">
                <golden-layout class="windows" :showPopoutIcon="false" :showMaximiseIcon="false">
                  <gl-row>
                    <gl-component title="component1" closable="false">
                      <h1>Component 1</h1>
                    </gl-component>
                    <gl-stack>
                      <gl-component title="component2">
                        <h1>Component 2</h1>
                      </gl-component>
                      <gl-component title="component3">
                        <h1>Component 3</h1>
                      </gl-component>
                    </gl-stack>
                  </gl-row>
                </golden-layout>
              </div>
            </template>
            <template slot="paneR">
              <div class="space space-terminal"><Console ref="console"/></div>
            </template>
          </split-pane>
        </template>
      </split-pane>
    </main>
    <footer class="status">
      <div class="connecting">
        <b-icon icon="check-network" size="is-small"></b-icon>frida@12.8.20, iOS 13.3 - Messages
      </div>
    </footer>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'
import debounce from 'debounce'
import colors from 'ansi-colors'

import MenuBar from './MenuBar.vue'
import SidePanel from '../views/SidePanel.vue'
import Console from '../components/Console.vue'

@Component({
  components: {
    MenuBar,
    SidePanel,
    Console
  }
})
export default class Workspace extends Vue {
  resizeEvent: Function = () => { /* placeholder */ }

  mounted() {
    const theConsole = this.$refs.console as Console
    const { term } = theConsole

    term.writeln(colors.cyan('Console Output'))
    term.writeln(colors.white.bgMagenta('Okay'))
    term.writeln(colors.redBright('Error'))
    for (let i = 0; i < 100; i++) {
      term.writeln(`plenty of logs: ${i}`)
    }
    term.write('Hello from \x1B[1;3;31mxterm.js\x1B[0m $ ')

    this.resizeEvent = debounce(theConsole.resize.bind(theConsole), 100)
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

  .connecting {
    background: #068068;
    display: inline-block;
    padding: 2px 4px;
    color: #fff;
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
</style>

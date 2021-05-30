<template>
  <div class="frame" refs="container">
  </div>
</template>

<script lang="ts">
import 'xterm/css/xterm.css'
import { FitAddon } from 'xterm-addon-fit'
import { Terminal } from 'xterm'
import { Component, Vue } from 'vue-property-decorator'

@Component
export default class Console extends Vue {
  public term = new Terminal({
    fontFamily: '"Fira Code", monospace',
    fontSize: 12,
    theme: {
      background: '#1e1e1e'
    }
  })

  fitAddon = new FitAddon()

  mounted() {
    const { term, fitAddon } = this
    term.loadAddon(fitAddon)
    term.open(this.$el as HTMLDivElement)
    fitAddon.fit()
  }

  resize() {
    this.fitAddon.fit()
  }

  beforeDestroy() {
    this.term.dispose()
  }
}
</script>

<style lang="scss" scoped>
.frame {
  height: 100%;
  overflow: hidden;
}
.xterm-viewport {
  overflow-y: hidden;
}
</style>

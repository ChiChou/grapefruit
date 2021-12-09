<template>
  <div class="browser-frame">
    <b-tabs v-model="tab" :animated="false">
      <b-tab-item label="Context">
        <JSValue :obj="context" />
      </b-tab-item>

      <b-tab-item label="Evaluate">
        <div class="editor" ref="container"></div>
        <div class="toolbar">
          <b-button icon-left="play" type="is-success" @click="run">Run (F4)</b-button>
        </div>

        <pre v-if="result" class="result">{{ result }}</pre>
      </b-tab-item>

    </b-tabs>
  </div>
</template>

<script lang="ts">
import * as monaco from 'monaco-editor'
import { Component, Prop, Watch } from 'vue-property-decorator'
import { rem2px } from '@/utils'
import Base from './Base.vue'
import JSValue from '@/components/JSValue.vue'

const WEBVIEW_JS = 'tabs.webview.javaascript'

@Component({
  components: {
    JSValue
  }
})
export default class JSCDetail extends Base {
  editor?: monaco.editor.ICodeEditor

  active = false
  context = {}
  result = ''
  tab = 0

  @Prop({ required: true })
  handle!: string

  createEditor() {
    const container = this.$refs.container as HTMLDivElement

    const value = localStorage.getItem(WEBVIEW_JS) || '// inject javascript to webview'
    const editor = monaco.editor.create(container, {
      value,
      language: 'javascript',
      theme: 'vs-dark',
      fontSize: rem2px(1),
      fontFamily: '"Fira Code", monospace'
    })

    this.editor = editor
    editor.addCommand(monaco.KeyCode.F4, () => this.run())
  }

  @Watch('tab')
  onTabChanged(newTab: number) {
    const { editor } = this
    if (newTab === 1) {
      if (!editor) this.createEditor()
      this.resize()
    }
  }

  mounted() {
    this.loading = true
    this.$rpc.jsc.dump(this.handle).then((ctx: object) => {
      this.context = ctx
    })
    this.loading = false
  }

  async run() {
    if (!this.editor) throw new Error('Unexpected error: editor is not ready')
    this.loading = true
    const code = this.editor.getValue()
    localStorage.setItem(WEBVIEW_JS, code)

    try {
      this.result = await this.$rpc.jsc.run(this.handle, code)
    } catch (e) {
      this.result = `${e}`
    } finally {
      this.loading = false
    }
  }

  resize() {
    const { editor } = this
    if (editor) setTimeout(() => editor.layout(), 0)
  }

  destroyed() {
    if (this.editor) {
      localStorage.setItem(WEBVIEW_JS, this.editor.getValue())
      this.editor.dispose()
    }
  }
}
</script>

<style lang="scss" scoped>
.browser-frame {
  padding: 10px;
}

.editor {
  height: 320px;
}

.toolbar, .result {
  margin-top: 10px;
}
</style>

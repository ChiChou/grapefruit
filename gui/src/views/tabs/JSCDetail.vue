<template>
  <div class="browser-frame">
    <h2>Context</h2>
    <pre>{{ context }}</pre>

    <h2>JavaScript</h2>
    <div class="editor" ref="container"></div>
    <div class="toolbar">
      <b-button icon-left="play" type="is-success" @click="run">Run (F4)</b-button>
    </div>

    <pre v-if="result" class="result">{{ result }}</pre>
  </div>
</template>

<script lang="ts">
import * as monaco from 'monaco-editor'
import { Component, Prop } from 'vue-property-decorator'
import { rem2px } from '../../utils'
import Base from './Base.vue'

const WEBVIEW_JS = 'tabs.webview.javaascript'

@Component
export default class JSCDetail extends Base {
  editor?: monaco.editor.ICodeEditor

  active = false
  context = {}
  result = ''

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
    editor.layout()
    editor.addCommand(monaco.KeyCode.F4, () => this.run())
  }

  mounted() {
    this.loading = true
    this.createEditor()
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
    if (this.editor) this.editor.layout()
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

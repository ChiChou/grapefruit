<template>
  <div class="browser-frame">
    <h2>Navigation</h2>
    <b-field>
      <b-input
        expanded
        placeholder="Open new URL"
        type="search"
        icon="apple-safari"
        @keydown.native.enter="navigate"
        v-model="url"
      >
      </b-input>
      <p class="control">
        <button class="button is-primary" @click="navigate">Navigate</button>
      </p>
    </b-field>

    <h2>JavaScript</h2>
    <div class="editor" ref="container"></div>
    <div class="toolbar">
      <b-button icon-left="play" type="is-success" @click="run">Run (F4)</b-button>
    </div>

    <pre v-if="result" class="result">{{ result }}</pre>
    <div v-if="prefs" class="prefs">
      <data-field class="plist dark" :depth="0" :field="{ value: prefs }" />
    </div>
  </div>
</template>

<script lang="ts">
import * as monaco from 'monaco-editor'
import DataField from '@/components/DataField.vue'
import { Component, Prop } from 'vue-property-decorator'
import { rem2px } from '@/utils'
import Base from './Base.vue'

const WEBVIEW_JS = 'tabs.webview.javaascript'

@Component({
  components: {
    DataField
  }
})
export default class WebViewDetail extends Base {
  editor?: monaco.editor.ICodeEditor

  active = false
  url = 'http://'
  result = ''
  prefs = ''

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
    this.$rpc.webview.url(this.handle).then((url: string) => { this.url = url })
    this.$rpc.webview.prefs(this.handle).then((prefs: string) => { this.prefs = prefs })
    this.loading = false
  }

  navigate() {
    this.loading = true
    this.$rpc.webview.navigate(this.handle, this.url).finally(() => {
      this.loading = false
    })
  }

  async run() {
    if (!this.editor) throw new Error('Unexpected error: editor is not ready')
    this.loading = true
    const code = this.editor.getValue()
    localStorage.setItem(WEBVIEW_JS, code)

    try {
      this.result = await this.$rpc.webview.run(this.handle, code)
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

.toolbar, .result, .prefs {
  margin-top: 10px;
}

</style>

<template>
  <div>
    <div class="editor" ref="container"></div>
  </div>
</template>

<script lang="ts">
import * as monaco from 'monaco-editor'
// import * as monaco from 'monaco-editor/esm/vs/editor/editor.api'

import { Component } from 'vue-property-decorator'
import InlinePreview from './InlinePreview.vue'
import { extname } from '../../utils'

const decoder = new TextDecoder()

@Component
export default class TextPreview extends InlinePreview {
  editor?: monaco.editor.ICodeEditor

  get syntax(): string {
    const ext = extname(this.path)
    if (typeof ext === 'undefined') return 'text'
    const mapping: { [key: string]: string } = {
      js: 'javascript',
      json: 'json',
      html: 'html',
      htm: 'html',
      csv: 'csv',
      sql: 'sql',
      yaml: 'yaml',
      yml: 'yaml',
      css: 'css',
      xml: 'xml',
      entitlements: 'xml'
    }

    return mapping[ext] || 'text'
  }

  mounted() {
    this.loading = true
    this.$rpc.fs.text(this.path).then((content: ArrayBuffer) => {
      const value = decoder.decode(content)
      this.editor = monaco.editor.create(this.$refs.container as HTMLElement, {
        value,
        language: this.syntax,
        readOnly: true,
        theme: 'vs-dark',
        fontSize: 16,
        fontFamily: '"Fira Code", monospace'
      })
    }).finally(() => {
      this.loading = false
    })
  }

  resize() {
    if (this.editor) this.editor.layout()
  }
}
</script>

<style scoped>
.editor {
  width: calc(100%);
  height: calc(100%);
  overflow: hidden;
}
</style>

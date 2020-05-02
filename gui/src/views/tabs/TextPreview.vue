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
  get syntax(): string {
    const ext = extname(this.path)
    const mapping = {
      js: 'javascript',
      json: 'json',
      html: 'html',
      htm: 'html',
      csv: 'csv',
      sql: 'sql',
      yaml: 'yaml',
      yml: 'yaml',
      css: 'css'
    }
    return mapping[ext] || 'text'
  }

  mounted() {
    this.loading = true
    this.$rpc.fs.text(this.path).then((content: ArrayBuffer) => {
      const value = decoder.decode(content)
      monaco.editor.create(this.$refs.container as HTMLElement, {
        value,
        language: this.syntax,
        readOnly: true,
        theme: 'vs-dark',
        fontSize: 16
      })
    }).finally(() => {
      this.loading = false
    })
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

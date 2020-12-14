<template>
  <div class="main">
    <header class="toolbar">
      <b-button icon-left="content-save" @click="save">Save</b-button>
      <b-button icon-left="play" @click="run">Run</b-button>
    </header>
    <main><div class="editor" ref="container"></div></main>
  </div>
</template>

<script lang="ts">
import Axios from 'axios'
import * as monaco from 'monaco-editor'
import { Component, Prop } from 'vue-property-decorator'
import { extname, rem2px } from '../../utils'

import Base from './Base.vue'

@Component({

})
export default class CodeRunner extends Base {
  editor?: monaco.editor.ICodeEditor

  @Prop({ default: '' })
  file!: string

  path = ''

  get syntax(): string {
    // todo: TypeScript
    const ext = extname(this.path)
    return ext === 'ts' ? 'typescript' : 'javascript'
  }

  async createEditor(container: HTMLDivElement, value?: string) {
    try {
      const types = (await Axios.get('/types')).data
      monaco.languages.typescript.javascriptDefaults.addExtraLib(types, 'frida-gum.d.ts')
    } finally {

    }

    const editor = monaco.editor.create(container, {
      value,
      language: 'javascript',
      theme: 'vs-dark',
      fontSize: rem2px(1),
      fontFamily: '"Fira Code", monospace'
    })
    // validation settings
    monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
      noSemanticValidation: true,
      noSyntaxValidation: false
    })
    // remove browser object models
    monaco.languages.typescript.javascriptDefaults.setCompilerOptions({
      target: monaco.languages.typescript.ScriptTarget.ES5,
      noLib: true,
      allowNonTsExtensions: true
    })

    editor.layout()
    editor.addCommand(monaco.KeyMod.CtrlCmd | monaco.KeyCode.KEY_S, () => this.save())
    return editor
  }

  async mounted() {
    this.loading = true
    const container = this.$refs.container as HTMLDivElement

    if (!this.file) {
      this.editor = await this.createEditor(container)
      this.loading = false
      return
    }

    this.path = this.file

    Axios.get(`/snippet/${this.path}`)
      .then(async({ data }) => {
        this.editor = await this.createEditor(this.$refs.container as HTMLDivElement, data)
      })
      .finally(() => {
        this.loading = false
      })
  }

  async save() {
    if (!this.editor) return

    const content = this.editor.getValue()
    const headers = { 'Content-Type': 'text/plain' }

    if (!this.path) {
      this.$buefy.dialog.prompt({
        message: 'Save the script',
        inputAttrs: { placeholder: 'snippet.js' },
        trapFocus: true,
        onConfirm: async(path) => {
          try {
            await Axios.put(`/snippet/${path}`, content, { headers })
            this.path = path
          } catch (e) {
            const reason = e.response.code === 404 ? 'Invalid filename' : 'Unknown reason'
            this.$buefy.toast.open(`Failed to save document: ${reason}`)
          }
        }
      })
      return
    }
    await Axios.put(`/snippet/${this.path}`, content, { headers })
  }

  async run() {
    const result = await this.$ws.send('userscript', this.editor?.getValue())
    console.log(result)
  }

  resize() {
    if (this.editor) this.editor.layout()
  }

  destroyed() {
    if (this.editor) this.editor.dispose()
  }
}

</script>

<style lang="scss" scoped>
.main {
  display: flex;
  flex-direction: column;
  overflow: hidden;
}

main {
  flex: 1;
}

.editor {
  height: 100%;
  width: 100%;
}
</style>

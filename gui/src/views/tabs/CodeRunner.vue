<template>
  <div class="main">
    <header class="toolbar">
      <b-field>
        <p class="control">
          <b-button icon-left="content-save" @click="save">Save</b-button>
        </p>
        <p class="control">
          <b-button icon-left="play" @click="run">Run</b-button>
        </p>
        <p class="control" v-if="uuid">
          <b-button icon-left="stop" @click="stop">Stop</b-button>
        </p>
        <p class="control">
          <b-button icon-left="download" @click="download">Download</b-button>
        </p>
      </b-field>
    </header>
    <main><div class="editor" ref="container"></div></main>
  </div>
</template>

<script lang="ts">
import Axios from 'axios'
import * as monaco from 'monaco-editor'
import { Component, Prop } from 'vue-property-decorator'
import { extname, rem2px } from '@/utils'
import { ConsoleModule } from '@/store/modules/console'
import { ContentType, IconType } from '@/store/types'

import DataField from '@/components/DataField.vue'
import Base from './Base.vue'

@Component({
  components: {
    DataField
  }
})
export default class CodeRunner extends Base {
  editor?: monaco.editor.ICodeEditor

  @Prop({ default: '' })
  file!: string

  @Prop({ default: '' })
  code!: string

  path = ''

  uuid: string = ''

  get syntax(): string {
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
      this.editor = await this.createEditor(container, this.code)
      this.loading = false
      return
    }

    this.path = this.file

    Axios.get(`/snippet/${this.path}`)
      .then(async({ data }) => {
        this.editor = await this.createEditor(container, data)
      })
      .finally(() => {
        this.loading = false
      })
  }

  save() {
    if (!this.editor) return

    const content = this.editor.getValue()
    const headers = { 'Content-Type': 'text/plain' }

    if (this.path) {
      Axios.put(`/snippet/${this.path}`, content, { headers }).then(() => {
        this.$buefy.snackbar.open('Saved')
      })
    } else {
      this.$buefy.dialog.prompt({
        message: 'Save the script',
        inputAttrs: { placeholder: 'snippet.js' },
        trapFocus: true,
        onConfirm: (path) => {
          Axios.put(`/snippet/${path}`, content, { headers }).then(() => {
            this.path = path
            this.$buefy.snackbar.open('Saved')
          }).catch(e => {
            const reason =
              e.response.code === 404 ? 'Invalid filename' : 'Unknown reason'
            this.$buefy.toast.open(`Failed to save document: ${reason}`)
          })
        }
      })
    }
  }

  async run() {
    if (!this.editor) return

    this.stop()
    const uuid = Math.random().toString(36).slice(2)
    this.uuid = uuid
    const src = this.editor.getValue()
    const result = await this.$ws.send('userscript', src, uuid)
    const source = await monaco.editor.colorize(src.trim(), 'javascript', {})

    ConsoleModule.log({
      type: ContentType.HTML,
      icon: IconType.In,
      content: source
    })

    ConsoleModule.log({
      icon: IconType.Out,
      content: result
    })

    this.$bus.$emit('switchTab', 'Output', 'Output')
  }

  download() {
    if (!this.editor) return
    const src = this.editor.getValue()
    const blob = new Blob([src], {type: 'text/javascript'})
    const elem = window.document.createElement('a')
    elem.href = window.URL.createObjectURL(blob)
    elem.download = this.path || 'snippet.js'
    document.body.appendChild(elem)
    elem.click()
    document.body.removeChild(elem)
  }

  stop() {
    if (this.uuid) {
      this.$ws.send('removescript', this.uuid)
      this.uuid = ''
    }
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

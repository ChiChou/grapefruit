<template>
  <div>
    <split-pane
      :min-percent="10"
      :default-percent="15"
      split="vertical"
      class="main"
      @resize="resize"
    >
      <template slot="paneL">
        <aside class="tables">
          <ul>
            <li v-for="(table, index) in tables" :key="index">
              <a @click="dump(table)"><b-icon icon="table" />{{ table }}</a>
            </li>
          </ul>
        </aside>
      </template>
      <template slot="paneR">
        <split-pane split="horizontal" :default-percent="20" :min-percent="10" @resize="resize">
          <template slot="paneL">
            <div class="editor" ref="container"></div>
          </template>
          <template slot="paneR">
            <article class="result">
              <nav>
                <b-button @click="execute" icon-left="play">Run (meta + Enter)</b-button>
                <p :class="{ 'has-text-danger': failed, 'has-text-success': !failed }" v-if="msg">{{ msg }}</p>
              </nav>
              <section classs="data">
                <b-table :data="data" :columns="columns" class="data-table"></b-table>
              </section>
            </article>
          </template>
        </split-pane>
      </template>
    </split-pane>
  </div>
</template>

<script lang="ts">
import * as monaco from 'monaco-editor'

import { Component } from 'vue-property-decorator'
import { rem2px, htmlescape } from '@/utils'
import Preview from './Preview.vue'

// eslint-disable-next-line quotes
const DEFAULT_SQL = `SELECT name FROM sqlite_master WHERE type ='table' AND name NOT LIKE 'sqlite_%';`

interface Column {
  field: string;
  label: string;
  width?: string;
  centered?: boolean;
  numeric?: boolean;
  sortable: true;
}

@Component
export default class SQLitePreview extends Preview {
  editor?: monaco.editor.IStandaloneCodeEditor
  tables: string[] = []
  handle?: string

  data: object[] = []
  columns: Column[] = []
  msg = ''
  failed = false

  set storedSQL(sql: string) {
    localStorage.setItem(`sql/${this.path}`, sql)
  }

  get storedSQL(): string {
    return localStorage.getItem(`sql/${this.path}`) || DEFAULT_SQL
  }

  mounted() {
    this.editor = monaco.editor.create(this.$refs.container as HTMLDivElement, {
      value: this.storedSQL,
      language: 'sql',
      theme: 'vs-dark',
      fontSize: rem2px(1),
      fontFamily: '"Fira Code", monospace'
    })
    this.editor.addAction({
      id: 'run-query',
      label: 'Execute Query',
      keybindings: [
        monaco.KeyCode.F5,
        monaco.KeyMod.CtrlCmd | monaco.KeyCode.Enter
      ],
      run: this.execute
    })

    this.loading = true
    this.$rpc.sqlite.tables(this.path)
      .then((tables: string[]) => { this.tables = tables })
    this.$rpc.sqlite.open(this.path)
      .then((handle: string) => { this.handle = handle })
      .finally(() => { this.loading = false })
  }

  async dump(table: string) {
    if (!this.editor) return
    const sql = `SELECT * from ${table};`
    this.editor.setValue(sql)
    this.loading = true
    this.failed = false
    try {
      const { header, data } = await this.$rpc.sqlite.dump(this.path, table)
      this.columns = header.map((item: [string, string]) => {
        const [name, type] = item
        return {
          field: name,
          label: name,
          sortable: true,
          numeric: ['INTEGER', 'REAL'].includes(type)
        }
      })

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      this.data = data.map((row: any[]) => {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const result: { [field: string]: any } = {}
        header.forEach((hdr: [string, string], i: number) => { result[hdr[0]] = row[i] })
        return result
      })
      this.storedSQL = sql
      this.msg = 'Table loaded'
    } catch (e) {
      this.$buefy.toast.open({
        type: 'is-danger',
        message: `Unexpected error: <br>${htmlescape('' + e)}`
      })
    } finally {
      this.loading = false
    }
  }

  async execute() {
    if (!this.editor) return
    const sql = this.editor.getValue()
    this.data = []
    this.columns = []
    this.loading = true
    this.failed = false
    this.msg = ''
    try {
      const data = await this.$rpc.sqlite.query(this.handle, sql)
      this.data = data
      this.columns = data.length > 0 ? data[0].map((e: string, i: number) => {
        const name = '#' + i
        return {
          label: name,
          field: i.toString(),
          sortable: true
        }
      }) : []
      this.storedSQL = sql
      this.msg = 'query successfully executed'
    } catch (e) {
      this.msg = (e as Error).toString()
      this.failed = true
      this.$buefy.toast.open({
        type: 'is-danger',
        message: `Unexpected error: <br>${htmlescape(this.msg)}`
      })
    } finally {
      this.loading = false
    }
  }

  destroyed() {
    if (this.handle) this.$rpc.sqlite.close(this.handle)
    if (this.editor) this.editor.dispose()
  }

  resize() {
    if (this.editor) this.editor.layout()
  }
}
</script>

<style lang="scss" scoped>
.frame {
  overflow: hidden;
}

pre.hidden {
  display: none;
}

.editor {
  height: 100%;
  width: 100%;
  // overflow: hidden;
}

.frame-main {
  width: 100%;
  height: 100%;
}

nav {
  padding: 10px;
  position: sticky;
  top: 0;
  left: 0;
  display: flex;
  align-items: center;
  background: #222;
  box-shadow: 0px 2px 4px #00000030;
  justify-content: space-between;
}

article.result {
  height: 100%;
  overflow: auto;
}

.tables {
  height: 100%;
  overflow: auto;

  ul {
    padding: 4px;

    li {
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }
  }
}

.data-table {
  word-wrap: break-word;
}
</style>

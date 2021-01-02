<template>
  <aside class="side-panel">
    <header>
      <b-progress class="thin" :class="{ show: loading }"></b-progress>
      <input v-model="keyword" placeholder="Search..." class="search" :disabled="loading">
      <div class="system-filter">
        <a class="reload" @click="reload"><b-icon icon="refresh" :custom-class="loading ? 'mdi-spin' : ''"/></a>
        <b-checkbox v-model="system">Include System Libraries</b-checkbox>
      </div>
    </header>

    <main class="scroll" :class="{ loading }">
      <b-table :data="list" default-sort="base" focusable :selected.sync="selected">
        <template slot-scope="props">
          <b-table-column field="base" label="Base" sortable numeric>
            <code>{{ props.row.base }}</code>
          </b-table-column>
          <b-table-column field="name" label="Name" sortable>
            <a @click="open(props.row)">{{ props.row.name }}</a>
          </b-table-column>
        </template>
      </b-table>
    </main>
    <!-- <section class="detail" v-if="selected">
      {{ selected }}
    </section> -->
  </aside>
</template>

<script lang="ts">
// eslint-disable-next-line
/// <reference path="../../frida.shim.d.ts" />

import { Component, Vue, Watch } from 'vue-property-decorator'

@Component
export default class Modules extends Vue {
  loading = false
  modules: Module[] = []
  list: Module[] = []
  keyword = ''
  selected: Module | null = null
  system = true

  @Watch('keyword')
  @Watch('system')
  search() {
    Vue.nextTick(() => {
      if (this.system && !this.keyword.length) this.list = this.modules

      this.list = this.modules.filter((mod: Module) => {
        if (!this.system) return mod.path.match(/^(\/private)?\/var/)
        if (this.keyword.length) return mod.name.toLowerCase().includes(this.keyword)
        return true
      })
    })
  }

  mounted() {
    this.reload()
  }

  reload() {
    this.loading = true
    this.$rpc.symbol.modules().then((result: Module[]) => {
      this.list = this.modules = result
      this.selected = null
    }).finally(() => {
      this.loading = false
    })
  }

  open(mod: Module) {
    this.$bus.$emit('openTab', 'ModuleInfo', mod.name, { module: mod })
  }
}
</script>

<style lang="scss" scoped>
.addr {
  font-family: monospace;
}

code {
  background: 0;
  padding: 0;
  color: #acacac;
  text-shadow: 1px 1px 1px #00000030;
}

.table td, .table th {
  padding: 0.25em 0.5em
}

.b-table table.table {
  table-layout: fixed !important;

  td[data-label=Name] {
    overflow: hidden;
  }
}

.reload {
  margin-right: 4px;
}

main.loading {
  display: none;
}

.system-filter {
  padding: 10px;
  display: flex;
  align-items: center;
  justify-items: center;
  background: #111;
  color: #777;

  > label {
    margin: auto;
  }
}
</style>

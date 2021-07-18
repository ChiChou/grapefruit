<template>
  <div class="pad">
    <h1 class="title">{{ module.name }}</h1>
    <h2 class="subtitle">{{ module.path }}</h2>

    <b-tabs v-model="activeTab" expanded :animated="false">
      <b-tab-item label="Imports">
        <header>
          <b-button @click="expandOrFold(true)" icon-left="plus" :loading="expandAllLoading">Expand All</b-button>
          <b-button @click="expandOrFold(false)" icon-left="minus">Fold All</b-button>
        </header>

        <ul class="imports">
          <li v-for="(group, i) in importGroups" :key="i" class="imports-group">
            <span @click="expandImportsGroup(group)">
              <b-icon icon="loading" custom-class="mdi-loading mdi-spin" v-if="group.loading" />
              <b-icon :icon="group.expanded ? 'minus-box' : 'plus-box' " v-else />
              {{ group.path }}
            </span>

            <ul v-if="group.expanded">
              <li v-for="(imp, j) in group.imps" :key="j" class="symbol">
                <b-icon :icon="imp.type" />
                <code>{{ imp.address }}</code>
                <span class="symbol-name">{{ imp.demangled || imp.name }}</span>
              </li>
            </ul>

            <p v-if="group.expanded && !group.loading && !group.imps.length">No symbol found</p>
          </li>
        </ul>
      </b-tab-item>
      <b-tab-item label="Exports">
        <b-field>
          <b-input v-model="keywordOfExport" value="" />
        </b-field>
        <ul>
          <li class="symbol" v-for="(exp, index) in exps.list" :key="index">
            <b-icon :icon="exp.type" />
            <code>{{ exp.address }}</code>
            <span class="symbol-name">{{ exp.demangled || exp.name }}</span>
          </li>
        </ul>
        <p v-if="exps.count > 200">Showing 200 items of {{ exps.count }}</p>
      </b-tab-item>
      <b-tab-item label="Symbols">
        <b-field>
          <b-input v-model="keywordOfSymbol" value="" />
        </b-field>
        <ul>
          <li class="symbol" v-for="(sym, index) in symbols.list" :key="index">
            <b-icon icon="function" v-if="sym.g" />
            <code>{{ sym.a }}</code>
            <span class="symbol-name">{{ sym.n }}</span>
          </li>
        </ul>
        <p v-if="symbols.count > 200">Showing 200 items of {{ symbols.count }}</p>
      </b-tab-item>
      <b-tab-item label="Classes">
        <ul>
          <li v-for="(clazz, index) in classes" :key="index">{{ clazz }}</li>
        </ul>
      </b-tab-item>
    </b-tabs>
  </div>
</template>

<script lang="ts">
// eslint-disable-next-line
/// <reference path="../../frida.shim.d.ts" />

import { BuefyNamespace } from 'buefy';
import debounce from 'lodash.debounce'
import { Component, Prop, Watch } from 'vue-property-decorator'
import Base from './Base.vue'

interface NativeSymbol {
  type: string;
  address: string;
  name: string;
}

type SymbolKind = 'function' | 'variable';

interface Group {
  path: string;
  imps: string[];
  expanded: boolean;
  loading: boolean;
}

interface Export {
  name: string;
  address: string;
  type: SymbolKind;
  demangled?: string;
}

interface Exports {
  count: number;
  list: Export[];
}

interface Symbol {
  n: string;
  g: boolean;
  a: string;
  t: SymbolKind;
}

interface Symbols {
  count: number;
  list: Symbol[];
}

@Component({
  watch: {
    keywordOfExport: debounce(function(this: ModuleInfo, newVal: string) {
      this.loadExported(newVal)
    }, 500),
    keywordOfSymbol: debounce(function(this: ModuleInfo, newVal: string) {
      this.loadSymbols(newVal)
    }, 500)
  }
})
export default class ModuleInfo extends Base {
  @Prop({ required: true })
  module!: Module

  importGroups: Group[] = []
  exps: Exports = { count: 0, list: [] }
  symbols: Symbols = { count: 0, list: [] }
  classes: string[] = []
  activeTab = 0
  tabLoading = [false, false, false, false]

  keywordOfExport = ''
  keywordOfSymbol = ''

  expandAllLoading = false

  async loadExported(keyword: string) {
    this.exps = await this.$rpc.symbol.exported(this.module.name, keyword)
  }

  async loadSymbols(keyword: string) {
    this.symbols = await this.$rpc.symbol.symbols(this.module.name, keyword)
  }

  @Watch('activeTab')
  onTabChanged(tab: number) {
    const loaders = [
      () => this.$rpc.symbol.importedModules(this.module.name).then((imps: string[]) => {
        this.importGroups = imps.map(path => {
          return {
            path,
            imps: [],
            expanded: false,
            loading: false
          }
        })
      }),
      () => this.loadExported(this.keywordOfExport),
      () => this.loadSymbols(this.keywordOfSymbol),
      () => this.$rpc.classdump.list(this.module.path).then((classes: string[]) => {
        this.classes = classes
      })
    ]

    this.tabLoading[tab] = true
    loaders[tab].call(this).finally(() => { this.tabLoading[tab] = false })
  }

  mounted() {
    this.onTabChanged(0)
  }

  async expandImportsGroup(group: Group) {
    if (group.expanded) {
      group.expanded = false
      return
    }

    group.loading = true
    try {
      group.expanded = true
      group.imps = await this.$rpc.symbol.imported(this.module.name, group.path)
    } finally {
      group.loading = false
    }
  }

  async expandOrFold(expand: boolean) {
    if (expand)
      this.expandAllLoading = true
    for (const group of this.importGroups) {
      if (expand && !group.expanded)
        await this.expandImportsGroup(group)
      group.expanded = expand
    }
    this.expandAllLoading = false
  }

  disasm(item: NativeSymbol) {
    const classPrefix = 'OBJC_CLASS_$_'
    if (item.type === 'variable' && item.name.startsWith(classPrefix)) {
      const name = item.name.substring(classPrefix.length)
      this.$bus.$emit('openTab', 'ClassInfo', 'Class: ' + name, { name })
    } else if (item.type === 'function') {
      const addr = item.address
      this.$bus.$emit('openTab', 'Disasm', 'Disasm @' + addr, { addr })
    }
  }
}
</script>

<style lang="scss">
.symbol {
  white-space: nowrap;
  text-overflow: ellipsis;
  overflow: hidden;
}
.symbol-name {
  font-family: monospace;
}

.imports-group {
  > span {
    cursor: pointer;
  }
}

ul.imports li > ul {
  margin-left: 1rem;
}
</style>

<template>
  <div class="pad module-info">
    <h1 class="title">{{ module.name }}</h1>
    <h2 class="subtitle">{{ module.path }}</h2>

    <b-tabs v-model="activeTab" expanded :animated="false">
      <b-tab-item label="Imports">
        <header>
          <b-button @click="expandOrCollapse(true)" icon-left="plus" :loading="expandAllLoading">Expand All</b-button>
          <b-button @click="expandOrCollapse(false)" icon-left="minus">Collapse All</b-button>
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
              <b-field class="actions">
                <p class="control">
                  <b-button icon-left="hook" />
                </p>
                <p class="control">
                  <b-button icon-left="code-tags"
                    @click="copy(module.name, exp.name, exp.type)" />
                </p>
                <p class="control">
                  <b-button icon-left="open-in-new" :disabled="exp.type !== 'function'"
                    @click="$bus.$emit('openTab', 'Disasm', 'Disasm @' + exp.address, { addr: exp.address })"/>
                </p>
              </b-field>
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
            <b-field class="actions">
              <b-button icon-left="open-in-new" :disabled="sym.type !== 'function'"
                @click="$bus.$emit('openTab', 'Disasm', 'Disasm @' + sym.address, { addr: sym.address })" />
            </b-field>
            <b-icon icon="comma" />
            <code>{{ sym.address }}</code>
            <span class="symbol-name">{{ sym.demangled || sym.name }}</span>
          </li>
        </ul>
        <p v-if="symbols.count > 200">Showing 200 items of {{ symbols.count }}</p>
      </b-tab-item>
      <b-tab-item label="Classes">
        <ul>
          <li v-for="(clazz, index) in classes" :key="index" class="symbol">
            <b-icon icon="code-braces" />
            <a @click="$bus.$emit('openTab', 'ClassInfo', 'Class: ' + clazz, { name: clazz })">
              <span class="symbol-name">{{ clazz }}</span>
            </a>
          </li>
        </ul>
      </b-tab-item>
    </b-tabs>

    <b-modal :active.sync="isCopyCodeActive" 
        aria-role="dialog"
        aria-label="Example Modal"
        aria-modal>
      <h1>Hook Template</h1>
      <pre v-if="codeTemplate.type !== 'function'">
Module.getExportByName('{{ codeTemplate.module }}', '{{ codeTemplate.name }}').readPointer()</pre>
      <pre v-else>
Interceptor.attach(
  Module.getExportByName('{{ codeTemplate.module }}', '{{ codeTemplate.name }}'),
  {
    onEnter(args) {
      console.log('{{ codeTemplate.name }} has been called')
    },
    onLeave(retval) {

    }
  })</pre>
    </b-modal>
  </div>
</template>

<script lang="ts">
// eslint-disable-next-line
/// <reference path="../../frida.shim.d.ts" />

import debounce from 'lodash.debounce'
import { Component, Prop, Watch } from 'vue-property-decorator'
import Base from './Base.vue'

type SymbolKind = 'function' | 'variable' | 'class';

interface Import {
  address: string;
  name: string;
  type: SymbolKind;
}

interface Group {
  path: string;
  imps: Import[];
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
  name: string;
  demangled?: string;
  global: boolean;
  address: string;
  type?: SymbolKind;
}

interface Symbols {
  count: number;
  list: Symbol[];
}

interface CodeSample {
  name: string;
  module: string;
  type: string;
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

  isCopyCodeActive = false
  codeTemplate: CodeSample = {
    module: '',
    name: '',
    type: ''
  }

  async loadExported(keyword: string) {
    this.exps = await this.$rpc.symbol.exported(this.module.name, keyword)
  }

  async loadSymbols(keyword: string) {
    this.symbols = await this.$rpc.symbol.symbols(this.module.name, keyword)
  }

  view(sym: Symbol) {}

  copy(mod: string, name: string) {
    this.codeTemplate.module = mod
    this.codeTemplate.name = name
    this.isCopyCodeActive = true
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

  async expandOrCollapse(expand: boolean) {
    if (expand)
      this.expandAllLoading = true
    for (const group of this.importGroups) {
      if (expand && !group.expanded)
        await this.expandImportsGroup(group)
      group.expanded = expand
    }
    this.expandAllLoading = false
  }

  viewImport(imp: Import) {
    const PREFIX = 'OBJC_CLASS_$_'
    if (imp.type === 'variable' && imp.name.startsWith(PREFIX)) {
      const name = imp.name.substring(PREFIX.length)
      this.$bus.$emit('openTab', 'ClassInfo', 'Class: ' + name, { name })
    } else if (imp.type === 'function') {
      const addr = imp.address
      this.$bus.$emit('openTab', 'Disasm', 'Disasm @' + addr, { addr })
    }
  }
}
</script>

<style lang="scss">
.module-info {
  .symbol {
    font-size: 1.25rem;
    white-space: nowrap;
    text-overflow: ellipsis;
    overflow: hidden;

    &:hover {
      background: rgba(0, 0, 0, .1)
    }
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

  .actions {
    float: right;
  }
}
</style>

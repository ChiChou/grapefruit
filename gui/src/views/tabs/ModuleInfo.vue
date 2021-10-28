<template>
  <div class="pad module-info">
    <h1 class="title">{{ module.name }}</h1>
    <h2 class="subtitle">{{ module.path }}</h2>

    <b-tabs expanded :animated="false">
      <b-tab-item label="Imports">
        <header>
          <b-button @click="expandOrCollapse(true)" icon-left="plus" :loading="expandAllLoading">Expand All</b-button>
          <b-button @click="expandOrCollapse(false)" icon-left="minus">Collapse All</b-button>
        </header>

        <ul class="imports">
          <li v-for="(group, i) in importGroups" :key="i" class="imports-group">
            <div @click="expandImportsGroup(group)" class="expand">
              <b-icon icon="loading" custom-class="mdi-loading mdi-spin" v-if="group.loading" />
              <b-icon :icon="group.expanded ? 'minus-box' : 'plus-box' " v-else />
              {{ group.path }}
            </div>

            <ul v-if="group.expanded">
              <li v-for="(imp, j) in group.imps" :key="j" class="symbol">
                <b-icon :icon="imp.type" />
                <code>{{ imp.address }}</code>
                <span class="symbol-name">{{ imp.demangled || imp.name }}</span>
                <b-field class="actions">
                  <!-- todo -->
                  <!-- <p class="control">
                    <b-button icon-left="hook" />
                  </p> -->
                  <p class="control">
                    <b-button icon-left="code-tags"
                      @click="code(group.path, imp.name, imp.type)" />
                  </p>
                  <p class="control">
                    <b-button icon-left="open-in-new" :disabled="!clickable(imp)" @click="view(imp)" />
                  </p>
                  <p class="control">
                    <b-button icon-left="magnify" @click="search(imp.name)" />
                  </p>
                </b-field>
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
                  @click="code(module.name, exp.name, exp.type)" />
              </p>
              <p class="control">
                <b-button icon-left="open-in-new" :disabled="!clickable(exp)" @click="view(exp)" />
              </p>
              <p class="control">
                <b-button icon-left="magnify" @click="search(exp.name)" />
              </p>
            </b-field>
            <a v-if="clickable(exp)" @click="view(exp)"><span class="symbol-name">{{ exp.demangled || exp.name }}</span></a>
            <span v-else class="symbol-name">{{ exp.demangled || exp.name }}</span>
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
              <b-button icon-left="open-in-new" :disabled="!clickable(sym)" @click="view(sym)" />
            </b-field>
            <b-icon icon="comma" />
            <code>{{ sym.address }}</code>
            <a v-if="clickable(sym)" @click="view(sym)"><span class="symbol-name">{{ sym.demangled || sym.name }}</span></a>
            <span v-else class="symbol-name">{{ sym.demangled || sym.name }}</span>
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
  </div>
</template>

<script lang="ts">
// eslint-disable-next-line
/// <reference path="../../frida.shim.d.ts" />

import Axios from 'axios'
import debounce from 'lodash.debounce'
import { Component, Prop } from 'vue-property-decorator'
import { basename, className, isClass, render } from '@/utils';
import Base from './Base.vue'

type SymbolKind = 'function' | 'variable' | 'class';

interface Import {
  address: string;
  name: string;
  demangled: string;
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

  async code(module: string, name: string, type: string) {
    const template = type === 'variable' ? 'pointer' : 'intercept'
    const vars = { 
      module: basename(module),
      name
    }

    const { data } = await Axios.get(`/template/${template}`)
    const code = render(data, vars)
    this.$bus.$emit('openTab', 'CodeRunner', 'New Hook Template', {
      file: '',
      code
    })
  }

  async load() {
    this.loading = true
    try {
      const imps = await this.$rpc.symbol.importedModules(this.module.name) as string[]
      this.importGroups = imps.map(path => {
        return {
          path,
          imps: [],
          expanded: false,
          loading: false
        }
      })

      await this.loadExported(this.keywordOfExport)
      await this.loadSymbols(this.keywordOfSymbol)
      this.classes = await this.$rpc.classdump.list(this.module.path)
    } finally {
      this.loading = false
    }
  }

  mounted() {
    this.load()
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

  clickable(entry: Import | Export | Symbol) {
    if (isClass(entry.name) && entry.type === 'variable') return true
    if (entry.type === 'function') return true
  }

  view(entry: Import | Export | Symbol) {
    if (isClass(entry.name) && entry.type === 'variable') {
      const name = className(entry.name)
      this.$bus.$emit('openTab', 'ClassInfo', 'Class: ' + name, { name })
    } else if (entry.type === 'function') {
      const addr = entry.address
      this.$bus.$emit('openTab', 'Disasm', 'Disasm @' + addr, { addr })
    }
  }

  hook(entry: Import | Export | Symbol) {
    // entry.name
    // entry.address
  }

  search(name: string) {
    const keyword = name.replace(/^OBJC_CLASS_\$_/, '')
    window.open('https://developer.apple.com/search/?q=' + keyword, '_blank')
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
    .expand {
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

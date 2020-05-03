<template>
  <div class="pad">
    <b-tabs>
      <b-tab-item label="Exports">
        <b-table
          :paginated="true"
          per-page="100"
          :data="exports">
          <b-input
            v-if="!props.column.numeric"
            slot="searchable"
            slot-scope="props"
            v-model="props.filters[props.column.field]"
            placeholder="Search..."
            icon="magnify"
            size="is-small" />

          <template slot-scope="props">
            <b-table-column field="type" label="Type" sortable>
              {{ props.row.type }}
            </b-table-column>
            <b-table-column field="name" label="Name" sortable searchable>
              <a @click="disasm(props.row)">{{ props.row.demangled || props.row.name }}</a>
            </b-table-column>
            <b-table-column field="address" label="Address" sortable numeric>
              <code>{{ props.row.address }}</code>
            </b-table-column>
          </template>
        </b-table>
      </b-tab-item>

      <!-- todo: slot -->
      <b-tab-item label="Imports">
        <b-table
          :paginated="true"
          per-page="100"
          :data="imports">

          <template slot-scope="props">
            <b-table-column field="type" label="Type" sortable>
              {{ props.row.type }}
            </b-table-column>
            <b-table-column field="name" label="Name" sortable searchable>
              <a @click="disasm(props.row)">{{ props.row.demangled || props.row.name }}</a>
            </b-table-column>
            <b-table-column field="address" label="Address" sortable numeric>
              <code>{{ props.row.address }}</code>
            </b-table-column>
            <b-table-column field="module" label="Module" sortable searchable>
              {{ props.row.module }}
            </b-table-column>
            <b-table-column field="slot" label="Slot" sortable>
              <code>{{ props.row.slot }}</code>
            </b-table-column>
          </template>

        </b-table>

      </b-tab-item>
    </b-tabs>
  </div>
</template>

<script lang="ts">
// eslint-disable-next-line
/// <reference path="../../frida.shim.d.ts" />

import { Component, Prop } from 'vue-property-decorator'
import Base from './Base.vue'

interface NativeSymbol {
  type: string;
  address: string;
  name: string;
}

@Component
export default class ModuleInfo extends Base {
  @Prop({ required: true })
  module!: Module

  imports: object[] = []
  exports: object[] = []

  mounted() {
    this.loading = true
    this.load().finally(() => { this.loading = false })
  }

  async load() {
    this.imports = await this.$rpc.symbol.imps(this.module.name)
    this.exports = await this.$rpc.symbol.exps(this.module.name)
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
/* todo: refactor */
td[data-label=Module], td[data-label=Module] {
  word-break: break-all;
  text-overflow: ellipsis;
  overflow: hidden;
}
</style>

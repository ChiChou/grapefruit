<template>
  <div class="pad">
    <h1>{{ module.name }} <span>@{{ module.base }}</span></h1>

    <b-tabs>
      <b-tab-item label="Exports">
        <b-table
          :paginated="true"
          per-page="100"
          :data="exports"
          :columns="colsForExports">
          <b-input
            v-if="!props.column.numeric"
            slot="searchable"
            slot-scope="props"
            v-model="props.filters[props.column.field]"
            placeholder="Search..."
            icon="magnify"
            size="is-small" />
        </b-table>
      </b-tab-item>

      <!-- todo: slot -->
      <b-tab-item label="Imports">
        <b-table
          :paginated="true"
          per-page="100"
          :data="imports"
          :columns="colsForImports">
          <b-input
            v-if="!props.column.numeric"
            slot="searchable"
            slot-scope="props"
            v-model="props.filters[props.column.field]"
            placeholder="Search..."
            icon="magnify"
            size="is-small" />
        </b-table>
      </b-tab-item>
    </b-tabs>
  </div>
</template>

<script lang="ts">
// eslint-disable-next-line
/// <reference path="../../frida.shim.d.ts" />

import { Component, Vue, Watch, Prop } from 'vue-property-decorator'
import Base from './Base.vue'

const basicColumns = [{
  field: 'type',
  label: 'Type',
  width: '80',
  sortable: true,
  numeric: false,
  searchable: false
}, {
  field: 'name',
  label: 'Name',
  width: '320',
  sortable: true,
  numeric: false,
  searchable: true
}, {
  field: 'address',
  label: 'Address',
  width: '80',
  sortable: true,
  numeric: true,
  searchable: false
}]

const importsColumns = basicColumns.slice()

importsColumns.push({
  field: 'module',
  label: 'Module',
  width: '640',
  sortable: true,
  numeric: false,
  searchable: true
}, {
  field: 'slot',
  label: 'Slot',
  width: '80',
  sortable: true,
  numeric: true,
  searchable: false
})

@Component
export default class ModuleInfo extends Base {
  @Prop({ required: true })
  module!: Module

  colsForExports = basicColumns
  colsForImports = importsColumns

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

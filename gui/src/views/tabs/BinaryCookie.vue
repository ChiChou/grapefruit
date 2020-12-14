<template>
  <div>
    <p><b-button icon-left="reload">Reload</b-button></p>
    <b-table :data="cookies" narrowed :loading="loading" default-sort="name">
      <template slot-scope="props">
        <b-table-column field="name" label="Name" sortable width="120">
          <span class="break-all">{{ props.row.name }}</span>
        </b-table-column>
        <b-table-column field="domain" label="Domain" sortable width="200">
          <span class="break-all">{{ props.row.domain }}</span>
        </b-table-column>
        <b-table-column field="path" label="Path" width="120">
          <span class="break-all">{{ props.row.path }}</span>
        </b-table-column>
        <b-table-column field="secure" label="Secure" width="80">
          <b-icon v-if="props.row.secure" icon="check" type="is-success" />
        </b-table-column>
        <b-table-column field="HTTPOnly" label="HTTPOnly" width="80">
          <b-icon v-if="props.row.HTTPOnly" icon="check" type="is-success" />
        </b-table-column>
        <b-table-column field="value" label="Value" sortable width="240">
          <div
            class="break-all value"
            contenteditable="true"
            tabindex="-1"
            @blur="dismiss(props.row, $event)"
            @focus="select"
            @keydown.esc="dismiss(props.row, $event)"
            @keydown.enter="submit(props.row, $event)"
            >{{ props.row.value }}</div>
        </b-table-column>
        <b-table-column field="SessionOnly" label="SessionOnly" width="80">
          <b-icon v-if="props.row.sessionOnly" icon="check" type="is-success" />
        </b-table-column>
        <b-table-column field="sameSitePolicy" label="SameSitePolicy" width="80">
          <span class="break-all">{{ props.row.sameSitePolicy }}</span>
        </b-table-column>
      </template>

      <div slot="empty" class="has-text-centered">
        <p v-show="!loading">
          <b-icon icon="info"></b-icon> <span>No binary cookie found</span>
        </p>
      </div>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Base from './Base.vue'

interface Cookie {
  name: string;
  value: string;
  domain: string;
  path: string;
  secure: boolean;
  HTTPOnly: boolean;
  sessionOnly: boolean;
  sameSitePolicy: string;
}

@Component
export default class CookieTab extends Base {
  cookies: Cookie[] = []

  mounted() {
    this.reload()
  }

  select() {
    requestAnimationFrame(() => document.execCommand('selectAll', false))
  }

  deselect() {
    const sel = window.getSelection()
    if (sel) sel.removeAllRanges()
  }

  dismiss(row: Cookie, event: Event) {
    const el = event.target as HTMLDivElement
    el.textContent = row.value
    el.blur()
    this.deselect()
  }

  submit(row: Cookie, event: Event) {
    const el = event.target as HTMLDivElement
    const value = el.textContent!
    this.loading = true
    row.value = value
    this.$rpc.cookies.write(row, value)
      .finally(() => { this.loading = false })
    el.blur()
    this.deselect()
  }

  reload() {
    this.loading = true
    this.$rpc.cookies.list()
      .then((data: Cookie[]) => { this.cookies = data })
      .finally(() => { this.loading = false })
  }
}
</script>

<style lang="scss" scoped>
.b-table {
  width: 100%;
}

.value {
  overflow-wrap: break-word;
  display: block;
  max-width: 600px;
}
</style>

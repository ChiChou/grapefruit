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
          <span class="break-all">{{ props.row.value }}</span>
        </b-table-column>
      </template>

      <div slot="empty" class="has-text-centered">
        <p v-show="!loading"><b-icon icon="info"></b-icon> <span>No binary cookie found</span></p>
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
  isSecured: boolean;
}

@Component
export default class CookieTab extends Base {
  cookies: Cookie[] = []

  mounted() {
    this.reload()
  }

  reload() {
    this.loading = true
    this.$rpc.cookies.list()
      .then((data: Cookie[]) => { this.cookies = data })
      .finally(() => { this.loading = false })
  }
}
</script>

<style lang="scss">
.b-table {
  width: 100%;
}
</style>

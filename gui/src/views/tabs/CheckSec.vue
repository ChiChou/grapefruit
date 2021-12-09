<template>
  <div class="pad">
    <section class="content">
      <h2>Binary Protections</h2>
      <b-field grouped group-multiline>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">Encrypted</b-tag>
            <b-tag type="is-info">{{ info.encrypted | bool }}</b-tag>
          </b-taglist>
        </div>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">PIE</b-tag>
            <b-tag type="is-success">{{ info.pie | bool }}</b-tag>
          </b-taglist>
        </div>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">Canary</b-tag>
            <b-tag type="is-success">{{ info.canary | bool }}</b-tag>
          </b-taglist>
        </div>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">ARC</b-tag>
            <b-tag type="is-success">{{ info.arc | bool }}</b-tag>
          </b-taglist>
        </div>
      </b-field>

      <h2>Entitlements</h2>
      <data-field class="plist dark" :depth="0" :field="{ value: info.entitlements }" />
    </section>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import DataField from '@/components/DataField.vue'
import Base from './Base.vue'

@Component({
  components: {
    DataField
  },
  filters: {
    bool: (val: boolean) => val ? 'yes' : 'no'
  }
})
export default class CheckSec extends Base {
  info = {}

  mounted() {
    this.title = 'Binary Protection & Entitlements'
    this.loading = true
    this.load().finally(() => {
      this.loading = false
    })
  }

  async load() {
    this.info = await this.$rpc.checksec()
  }
}
</script>

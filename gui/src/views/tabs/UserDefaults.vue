<template>
  <div class="pad">
    <data-field class="plist dark" :depth="0" :field="{ value }" />
  </div>
</template>
<script lang="ts">
import { Component } from 'vue-property-decorator'
import Base from './Base.vue'
import DataField from '@/components/DataField.vue'

@Component({
  components: {
    DataField
  }
})
export default class CookieTab extends Base {
  value = {}

  mounted() {
    this.title = 'NSUserDefaults'
    this.load()
  }

  async load() {
    this.loading = true
    try {
      this.value = await this.$rpc.info.userDefaults()
    } finally {
      this.loading = false
    }
  }
}
</script>

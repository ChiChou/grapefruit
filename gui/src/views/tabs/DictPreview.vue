<template>
  <div class="pad">
    <data-field class="plist dark" :depth="0" :field="{ value }" />
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Preview from './Preview.vue'
import DataField from '@/components/DataField.vue'
import { extname } from '@/utils'

@Component({
  components: {
    DataField
  }
})
export default class DictPreview extends Preview {
  value?: object = {}

  mounted() {
    this.loading = true
    this.load().finally(() => { this.loading = false })
  }

  async load() {
    const extension = extname(this.path)
    if (extension === 'json') {
      const url = await this.link()
      const response = await fetch(url)
      const source = await response.text()
      this.value = JSON.parse(source)
    } else {
      this.value = await this.$rpc.fs.plist(this.path)
    }
  }
}
</script>

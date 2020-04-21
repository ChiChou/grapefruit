<template>
  <div class="frame">
    <sub-view-loading v-if="loading" />
    <div class="content" v-else>
      <h1><img v-if="icon" :src="icon" width="32"> {{ info.name }} {{ info.semVer }}</h1>
      <dl><dt>Identifier</dt><dd>{{ info.id }}</dd></dl>
      <dl><dt>Container</dt><dd>{{ info.home }}</dd></dl>
      <dl><dt>Temporary Directory</dt><dd>{{ info.tmp }}</dd></dl>
      <dl><dt>Identifier</dt><dd>{{ info.id }}</dd></dl>
      <dl><dt>Mininal OS Requirement</dt><dd>{{ info.minOS }}</dd></dl>

      <data-field class="plist dark" :depth="0" :field="{ value: info.json }" />
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'
import SubViewLoading from '../../components/SubViewLoading.vue'
import DataField from '../../components/DataField.vue'

@Component({
  components: {
    SubViewLoading,
    DataField
  }
})
export default class Workspace extends Vue {
  info: object = {}
  loading = false
  icon?: string = ''

  mounted() {
    this.loading = true
    this.load().finally(() => { this.loading = false })
  }

  async load() {
    this.info = await this.$rpc.info.info()
    const data = await this.$rpc.info.icon()
    if (!data.length) return // todo: placeholder
    const blob = new Blob([data])
    this.icon = URL.createObjectURL(blob)
  }
}
</script>

<style lang="scss" scoped>
.frame {
  height: 100%;
}
.content {
  padding: 20px;
}

h1 {
  font-weight: 100;
}

.plist {
  width: 100%;
  word-break: break-all;
}
</style>

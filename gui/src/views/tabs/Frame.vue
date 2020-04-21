<template>
  <div class="subview-container">
    <component v-if="component" :is="component" v-bind="data" />
  </div>
</template>

<script lang="ts">
import TextViewer from './TextViewer.vue'
import Info from './Info.vue'

import { Component, Vue, Prop } from 'vue-property-decorator'

@Component({
  components: {
    TextViewer,
    Info
  }
})
export default class Workspace extends Vue {
  @Prop({ default: () => { return {} } })
  data?: object

  @Prop()
  component?: string
}
</script>

<style>
.subview-container {
  overflow-y: scroll;
  height: 100%;
}
</style>

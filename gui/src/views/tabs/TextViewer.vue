<template>
  <pre>{{ text }}</pre>
</template>

<script lang="ts">
import { Component, Vue, Prop } from 'vue-property-decorator'

@Component
export default class TextViewer extends Vue {
  @Prop()
  text?: string
}
</script>

<style scoped>
pre {
  height: 100%;
}
</style>

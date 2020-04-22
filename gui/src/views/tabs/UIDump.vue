<template>
  <div>
    <textarea readonly v-model="text"></textarea>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Base from './Base.vue'

@Component
export default class UISnapShot extends Base {
  text = ''

  mounted() {
    this.loading = true
    this.$rpc.ui.dump().then((text: string) => {
      this.text = text
    }).finally(() => {
      this.loading = false
    })
  }
}
</script>

<style scoped>
textarea {
  font-family: monospace;
  width: 100%;
  height: calc(100% - 6px);
  background: #222;
  color: #d0d0d0;
  padding: 20px;
  outline: none;
}
</style>

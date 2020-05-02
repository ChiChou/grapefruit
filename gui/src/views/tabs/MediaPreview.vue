<template>
  <div v-if="alive">
    <b-progress v-if="buffering" :value="progress" show-value format="percent" />

    <video v-if="source" width="100%" height="100%" controls autoplay>
      <source :src="source">
    </video>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Preview from './Preview.vue'

@Component
export default class MediaPreview extends Preview {
  alive = true
  progress = 0
  buffering = false
  blob?: Blob
  source?: string | null = null

  mounted() {
    this.alive = true
    this.load()
  }

  beforeDestroy() {
    this.alive = false
    if (this.source) URL.revokeObjectURL(this.source)
  }

  async load() {
    const url = await this.link()
    this.buffering = true
    this.progress = 0

    const blob = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('GET', url)
      xhr.responseType = 'blob'
      xhr.onprogress = ev => { this.progress = ev.loaded * 100 / ev.total }
      xhr.onload = () => resolve(xhr.response)
      xhr.onerror = () => reject(new Error(`xhr error: ${xhr.status} ${xhr.statusText}`))
      xhr.send()
    }) as Blob

    this.buffering = false
    this.blob = blob
    this.source = URL.createObjectURL(blob)
  }
}
</script>

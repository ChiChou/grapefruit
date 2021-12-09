<template>
  <div class="stage">
    <b-progress v-if="buffering" :value="progress" show-value format="percent" type="is-dark" />

    <component v-if="source" :is="player" controls="controls" autoplay>
      <source :src="source">
    </component>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Preview from './Preview.vue'
import { filetype } from '@/utils'

@Component
export default class MediaPreview extends Preview {
  progress = 0
  buffering = false
  blob?: Blob
  source?: string | null = null

  get player() {
    return filetype(this.path)
  }

  mounted() {
    this.load()
  }

  destroyed() {
    if (this.source) URL.revokeObjectURL(this.source)
    this.source = null
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

<style lang="scss" scoped>
.stage {
  min-height: 100%;
  display: flex;
  align-items: center;
  justify-items: center;

  .progress-wrapper {
    margin: auto;
    width: 75%;
    height: 16px;
  }
}

audio {
  width: 480px;
  height: 48px;
  margin: auto;
}

video {
  width: 100%;
  height: 100%;
  background: #000;
}
</style>

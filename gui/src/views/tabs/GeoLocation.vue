<template>
  <div>
    <iframe src="/picker.html"/> 
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Base from './Base.vue'

@Component
export default class GeoLocation extends Base {
  onmessage(e: MessageEvent) {
    const { event } = e.data;
    if (event === 'GPS_SIMULATE') {
      this.$rpc.geolocation.fake(e.data.lat, e.data.lng)
    } else if (event === 'STOP_GPS_SIMULATE') {
      this.$rpc.geolocation.dismiss()
    }
  }

  mounted() {
    this.title = 'GeoLocation Simulator'
  }

  created() {
    window.addEventListener('message', this.onmessage)
  }

  destroyed() {
    window.removeEventListener('message', this.onmessage)
  }
}
</script>

<style scoped>
iframe {
  width: 100%;
  height: 100%;
}
</style>
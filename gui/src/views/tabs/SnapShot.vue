<template>
  <div class="frame-center pad">
    <p v-if="failed">{{ error }}</p>
    <img v-else :src="url">
  </div>
</template>

<script lang="ts">
import { Component, Prop } from 'vue-property-decorator'
import ScreenShot from '../../components/ScreenShot.vue'
import Base from './Base.vue'

@Component({
  components: {
    ScreenShot
  }
})
export default class SnapShot extends Base {
  @Prop()
  device?: string

  failed = false
  url = 'data:null'
  error?: string

  mounted() {
    this.loading = true

    fetch(`/api/device/${this.device}/screen?t=` + Math.random())
      .then(r => {
        if (r.ok) return r.blob()
        r.text().then(t => {
          this.error = t
          this.failed = true
        })
      })
      .finally(() => { this.loading = false })
  }

  beforeDestroy() {
    if (this.url) {
      URL.revokeObjectURL(this.url)
    }
  }
}
</script>

<style lang="scss" scoped>
.frame-center {
  height: 100%;

  > img {
    display: block;
    margin: auto;
    width: auto;
  }
}
</style>

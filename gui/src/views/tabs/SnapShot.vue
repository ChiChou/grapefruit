<template>
  <div class="frame-center pad">
    <img :src="url" @load="loading = false" @error="loading = false">
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

  mounted() {
    this.loading = true
  }

  get url() {
    return `/api/device/${this.device}/screen?t=` + Math.random()
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

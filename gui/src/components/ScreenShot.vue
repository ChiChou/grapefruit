<template>
  <div class="screenshot">
    <a v-if="device" :href="url" target="_blank" class="frame">
      <div class="placeholder" v-if="loading">
        <Loading v-if="loading" class="loading" size="120" />
      </div>
      <img :src="url" width="320" @error="onerror" @load="loading = false" :class="{ loading }">
    </a>
  </div>
</template>

<script lang="ts">
import { Vue, Component, Prop } from 'vue-property-decorator'
import Loading from '../components/Loading.vue'

@Component({
  components: {
    Loading
  }
})
export default class ScreenShot extends Vue {
  loading = false
  fail = false
  token = Math.random()

  @Prop({ default: true })
  frame?: boolean

  @Prop()
  device!: string;

  refresh() {
    this.token = Math.random()
  }

  get url() {
    return `/api/device/${this.device}/screen?t=${this.token}`
  }

  mounted() {
    this.loading = true
    this.fail = false
    this.refresh()
  }

  onerror() {
    this.loading = false
    this.fail = true
  }
}
</script>

<style lang="scss" scoped>
.screenshot {
  .placeholder {
    position: relative;
    min-height: 480px;
    background: #000;

    > .loading {
      position: absolute;
      left: 50%;
      top: 50%;
      margin-top: -40px;
      margin-left: -40px;
    }
  }

  a {
    display: block;
    margin-bottom: 20px;

    img, .placeholder {
      border: 10px solid #000000ad;
      border-radius: 20px;

      @media (max-width: 1800px) {
        width: 240px;
      }

      @media (min-width: 1801px) {
        width: 320px;
      }
    }

    img.loading {
      visibility: hidden;
    }
  }
}
</style>

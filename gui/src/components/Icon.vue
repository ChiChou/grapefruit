<template>
  <canvas ref="icon" :width="w" :height="h"></canvas>
</template>

<script lang="ts">
import { Component, Prop, Watch, Vue } from 'vue-property-decorator'

interface Icon {
  width: number;
  height: number;
  pixels: string;
}

@Component
export default class IconView extends Vue {
  @Prop()
  icon!: Icon

  @Prop()
  width!: number

  @Prop()
  height!: number

  $refs!: {
    icon: HTMLCanvasElement;
  }

  mounted() {
    this.paint()
  }

  get w() {
    return (this.width > 0 ? this.width : this.icon && this.icon.width) || 32
  }

  get h() {
    return (this.height > 0 ? this.height : this.icon && this.icon.height) || 32
  }

  @Watch('icon')
  private navigate() {
    this.paint()
  }

  paint() {
    const canvas = this.$refs.icon
    if (!this.icon) {
      return
    }

    const ctx = canvas.getContext('2d')
    if (!ctx) {
      return
    }

    const { width, height, pixels } = this.icon
    const imageData = ctx.createImageData(width, height)
    let decoded: string
    try {
      decoded = atob(pixels)
    } catch (ex) {
      return
    }
    const buf = Uint8ClampedArray.from(decoded, c => c.charCodeAt(0))
    imageData.data.set(buf)
    ctx.clearRect(0, 0, canvas.width, canvas.height)
    ctx.putImageData(
      imageData,
      (canvas.width - width) / 2,
      (canvas.height - height) / 2
    )
    ctx.scale(canvas.width / width, canvas.height / height)
  }
}
</script>

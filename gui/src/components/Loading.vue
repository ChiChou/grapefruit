<template>
  <div>
    <div class="loading-icon-placeholder" ref="frame" :style="{ height: size, width: size }">
      <div class="lds-ripple"><div></div><div></div></div>
    </div>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop, Watch } from 'vue-property-decorator'

@Component
export default class Loading extends Vue {
  @Prop({ default: 80 })
  size!: number

  @Watch('size')
  private resize(value: number) {
    (this.$refs.frame as HTMLDivElement).style.transform = `scale(${(value / 80)})`
  }

  mounted() {
    this.resize(this.size)
  }
}
</script>
<style>
.loading-icon-placeholder {
  transform-origin: center;
}
.lds-ripple {
  display: inline-block;
  position: relative;
  width: 80px;
  height: 80px;
}
.lds-ripple div {
  position: absolute;
  border: 4px solid #fff;
  opacity: 1;
  border-radius: 50%;
  animation: lds-ripple 1s cubic-bezier(0, 0.2, 0.8, 1) infinite;
}
.lds-ripple div:nth-child(2) {
  animation-delay: -0.5s;
}
@keyframes lds-ripple {
  0% {
    top: 40px;
    left: 40px;
    width: 0;
    height: 0;
    opacity: 1;
  }
  100% {
    top: 0px;
    left: 0px;
    width: 80px;
    height: 80px;
    opacity: 0;
  }
}
</style>

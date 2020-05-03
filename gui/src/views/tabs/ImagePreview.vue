<template>
  <div>
    <div class="stage">
      <img v-if="url" :src="url">
    </div>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import InlinePreview from './InlinePreview.vue'

@Component
export default class ImagePreview extends InlinePreview {}
</script>

<style lang="scss" scoped>
.stage {
  display: flex;
  min-height: 100%;
  justify-content: center;
  align-items: center;
}
</style>

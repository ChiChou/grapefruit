<template>
  <embed v-if="url" :src="url" type="application/pdf">
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import InlinePreview from './InlinePreview.vue'

@Component
export default class PDFPreview extends InlinePreview {}
</script>

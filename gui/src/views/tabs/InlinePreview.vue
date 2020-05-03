<script lang="ts">

import { Component } from 'vue-property-decorator'

import Preview from './Preview.vue'

@Component
export default class InlinePreview extends Preview {
  url?: string | null = null

  mounted() {
    this.link().then((url: string) => { this.url = url })
  }
}
</script>

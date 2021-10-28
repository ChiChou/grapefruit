<template>
  <div>

  </div>
</template>

<script lang="ts">
import { Component, Vue, Watch } from 'vue-property-decorator'

export default class Workspace extends Vue {

  mounted() {
    this.$bus.$on('addHook', this.onAddHook)
    this.$bus.$on('removeHook', this.onRemoveHook)
  }

  onRemoveHook() {
    // todo:
  }

  onAddHook() {
    // todo:
  }
}

</script>
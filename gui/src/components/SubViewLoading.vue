<template>
  <div class="spin">
    <loading />
  </div>
</template>

<script lang="ts">
import { Component, Prop, Vue } from 'vue-property-decorator'
import Loading from './Loading.vue'

@Component({
  components: {
    Loading
  }
})
export default class Workspace extends Vue {}
</script>

<style lang="scss" scoped>
.spin {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;

  .loading {
    margin: auto;
  }
}
</style>

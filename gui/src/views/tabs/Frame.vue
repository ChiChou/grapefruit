<template>
  <div class="subview-container">
    <div v-if="loading" class="subview-spinner">
      <loading />
    </div>
    <component
      v-if="component"
      class="frame"
      :is="component"
      v-bind="data"
      v-bind:loading.sync="loading"
      :class="{ loading }"
    />
  </div>
</template>

<script lang="ts">
import TextViewer from './TextViewer.vue'
import CheckSec from './CheckSec.vue'
import SnapShot from './SnapShot.vue'
import UIDump from './UIDump.vue'
import Info from './Info.vue'
import Url from './URL.vue'

import Loading from '../../components/Loading.vue'

import { Component, Vue, Prop } from 'vue-property-decorator'

@Component({
  components: {
    Loading,
    Url,
    TextViewer,
    CheckSec,
    UIDump,
    SnapShot,
    Info
  }
})
export default class Frame extends Vue {
  @Prop({
    default: () => {
      return {}
    }
  })
  data?: object

  loading = false

  @Prop()
  component?: string
}
</script>

<style lang="scss">
.subview-container {
  overflow-y: auto;
  height: 100%;

  > .frame {
    height: 100%;

    &.loading {
      visibility: hidden;
    }

    &.pad {
      padding: 20px;

      > h1 {
        font-weight: 100;
        margin: 0 0 20px 0;
        font-size: 2rem;
      }
    }
  }
}

.subview-spinner {
  display: flex;
  align-items: center;
  justify-content: center;
  height: 100%;

  .loading {
    margin: auto;
  }
}
</style>

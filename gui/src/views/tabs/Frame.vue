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
import CheckSec from './CheckSec.vue'
import SnapShot from './SnapShot.vue'
import UIDump from './UIDump.vue'
import Info from './Info.vue'
import Url from './URL.vue'
import KeyChain from './KeyChain.vue'
import Cookies from './BinaryCookie.vue'
import UserDefaults from './UserDefaults.vue'
import ClassInfo from './ClassInfo.vue'
import ModuleInfo from './ModuleInfo.vue'

import Disasm from './Disasm.vue'
import Preview from './Preview.vue'
import MediaPreview from './MediaPreview.vue'
import DictPreview from './DictPreview.vue'
import PDFPreview from './PDFPreview.vue'
import ImagePreview from './ImagePreview.vue'
import TextPreview from './TextPreview.vue'
import SQLitePreview from './SQLitePreview.vue'
import UnknownPreview from './UnknownPreview.vue'

import CodeRunner from './CodeRunner.vue'
import WebViewDetail from './WebViewDetail.vue'

import Loading from '../../components/Loading.vue'

import { Component, Vue, Prop } from 'vue-property-decorator'
import { Container } from 'golden-layout'

@Component({
  components: {
    Loading,
    Url,
    KeyChain,
    Cookies,
    UserDefaults,
    CheckSec,
    UIDump,
    SnapShot,
    Info,
    ClassInfo,
    ModuleInfo,
    Disasm,

    MediaPreview,
    Preview,
    DictPreview,
    PDFPreview,
    ImagePreview,
    TextPreview,
    SQLitePreview,
    UnknownPreview,

    CodeRunner,
    WebViewDetail
  }
})
export default class Frame extends Vue {
  @Prop({
    default: () => {
      return {}
    }
  })
  data?: object

  @Prop({ required: true })
  container!: Container

  loading = false

  @Prop({ required: true })
  component!: string

  close() {
    this.container.close()
  }
}
</script>

<style lang="scss">
.subview-container {
  overflow-y: auto;
  height: 100%;

  > .frame {
    height: 100%;
    min-height: 100%;

    &.loading {
      visibility: hidden;
      height: 0;
      overflow: hidden;
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

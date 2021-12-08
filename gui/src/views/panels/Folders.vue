<template>
  <aside class="finder">
    <header>
      <b-progress class="thin" :class="{ show: loading }"></b-progress>
      <b-tabs v-model="index" expanded class="header-only">
        <b-tab-item label="Home" icon="folder-home-outline" />
        <b-tab-item label="Bundle" icon="folder-cog-outline" />
      </b-tabs>
    </header>

    <main>
      <section class="tree">
        <FolderTree :loading.sync="loading" :root="root" cwd="/" :depth="0" :item="{ type: 'directory', name: root }" />
      </section>
    </main>
  </aside>
</template>

<script lang="ts">
import { Component, Vue, Watch } from 'vue-property-decorator'
import FolderTree from '@/components/FolderTree.vue'
import { Finder } from '@/interfaces'
import { FinderModule } from '@/store/modules/finder'

@Component({
  components: {
    FolderTree
  }
})
export default class Files extends Vue {
  index = 0
  loading = false
  selected?: Finder.Item | null = null
  highlight?: FolderTree | null = null

  get root() {
    return ['home', 'bundle'][this.index]
  }

  @Watch('index')
  onRootChanged(val: number) {
    this.$bus.$emit('switchTab', 'Finder', 'Finder')
    if (val === 0) {
      FinderModule.goHome()
    } else {
      FinderModule.goApp()
    }
  }

  mounted() {
    this.$on('select', (el: FolderTree) => {
      if (this.highlight && this.highlight !== el) {
        this.highlight.dismiss()
      }

      this.highlight = el
      this.selected = el.item
    })
  }
}
</script>

<style lang="scss" scoped>
h2 {
  padding: 10px;
  background: #1b1b1b;
  color: #999;
}

aside.finder {
  display: flex;
  flex-direction: column;
  height: 100%;

  > main {
    flex: 1;
    overflow: auto;
    display: flex;
    flex-direction: column;

    > .tree {
      padding: 4px 0;
      flex: 1;
      overflow: auto;
    }

    > .detail {
      > .path {
        color: #ffc107;
      }

      p {
        margin-bottom: 0.125rem;

        &.download {
          margin-top: 0.5rem;
        }
      }
      word-break: break-all;
      padding: 10px;
      color: #c7c7c7;
      text-shadow: 1px 1px 1px #00000030;
      background: #00000030;
    }
  }
}

.b-tabs.is-fullwidth {
  .tabs {
    margin-bottom: 0 !important;
  }
  .tab-content {
    display: none !important;
  }
}

</style>

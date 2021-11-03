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
        <FileTree :loading.sync="loading" :root="root" cwd="/" :depth="0" :item="{ type: 'directory', name: root }" />
      </section>
      <section class="detail" v-if="selected">
        <p class="path">{{ selected.path }}</p>
        <p>
          {{ perm(selected.attribute.permission) }}
          {{ selected.attribute.owner }}:{{ selected.attribute.group }}
          {{ readableSize(selected.attribute.size) }}
        </p>

        <p>{{ selected.attribute.type }}</p>

        <p>Created: {{ selected.attribute.creation }}</p>
        <p>Modified: {{ selected.attribute.modification }}</p>
        <p>Protection: {{ selected.attribute.protection }}</p>
      </section>
    </main>
  </aside>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'
import FileTree from '../../components/FileTree.vue'
import { Finder } from '../../../interfaces'
import { humanFileSize } from '@/utils'

@Component({
  components: {
    FileTree
  }
})
export default class ClassInfo extends Vue {
  index = 0
  loading = false
  selected?: Finder.Item | null = null
  highlight?: FileTree | null = null

  get root() {
    return ['home', 'bundle'][this.index]
  }

  get perm() {
    return (val: number) => val.toString(8)
  }

  get readableSize() {
    return (val: number) => humanFileSize(val)
  }

  mounted() {
    this.$on('select', (el: FileTree) => {
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

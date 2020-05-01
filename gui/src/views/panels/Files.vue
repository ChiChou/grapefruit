<template>
  <aside class="explorer">
    <header>
      <b-tabs v-model="index" expanded class="header-only sticky">
        <b-tab-item label="Home" icon="folder-home-outline" />
        <b-tab-item label="Bundle" icon="folder-cog-outline" />
        <!-- <b-tab-item label="tmp" icon="timer-outline" /> -->
      </b-tabs>
    </header>

    <main>
      <FileTree :root="root" cwd="/" :depth="0" :item="{ type: 'directory', name: root }" />
    </main>
  </aside>
</template>

<script lang="ts">
import { Prop, Component, Watch, Vue } from 'vue-property-decorator'
import FileTree from '../../components/FileTree.vue'

interface Context {
  tmp?: string;
  bundle?: string;
  home?: string;
}

@Component({
  components: {
    FileTree
  }
})
export default class ClassInfo extends Vue {
  ctx: Context = {}
  index = 0
  loading = false

  get root() {
    return ['home', 'bundle'][this.index]
  }
}
</script>

<style lang="scss" scoped>
h2 {
  padding: 10px 20px;
  background: #1b1b1b;
  color: #999;
}

aside.explorer {
  display: flex;
  flex-direction: column;
  height: 100%;

  > header {

  }

  > main {
    flex: 1;
    overflow: auto;
    padding: 0 10px 10px 10px;
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

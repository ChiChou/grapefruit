<template>
  <ul class="file-tree-list">
    <div v-if="depth > 0" :style="{ marginLeft: (depth - 1) * 20 + 'px' }">
      <a v-if="isDir" @click="expanded = !expanded">
        <b-icon v-if="loading" icon="loading" size="is-small" custom-class="mdi-spin" />
        <b-icon v-else :icon="icon" />
      </a>
      <b-icon v-else :icon="icon" /><span @dblclick="open">{{ item.name }}</span>
    </div>
    <li v-for="(child, index) in children" :key="index">
      <FileTree :root="root" :cwd="cwd + '/' + child.name" :depth="depth + 1" :item="child" />
    </li>
  </ul>
</template>

<script lang="ts">
import { Prop, Component, Watch, Vue } from 'vue-property-decorator'
import { CreateElement, VNode } from 'vue'

interface Item {
  type: 'directory' | 'file';
  name: string;
  path: string;
  attribute: object;
}

@Component({
  name: 'FileTree'
})
export default class FileTree extends Vue {
  private _loading = false

  expanded = false
  children: Item[] = []
  loading = false

  @Prop({ required: true })
  item!: Item

  @Prop({ default: 0 })
  depth: number

  @Prop({ required: true })
  root: string

  @Prop({ required: true })
  cwd: string

  get icon() {
    if (!this.isDir) {
      const { name } = this.item
      const lastIndex = name.lastIndexOf('.')
      if (lastIndex > -1) {
        const ext = name.substr(lastIndex + 1).toLowerCase()
        // todo: for of
        if (/^(jpe?g|png|gif)$/.exec(ext)) return 'file-image-outline'
        if (ext === 'txt') return 'file-document-outline'
        if (ext === 'pdf') return 'file-pdf-outline'
        if (ext === 'js') return 'language-javascript'
        if (ext === 'plist') return 'cog-box'
        if (ext === 'dylib') return 'cogs'
        if (/^html?$/.exec(ext)) return 'language-html5'
        if (ext === 'xml') return 'xml'
        if (/^docx?/.exec(ext)) return 'file-word-outline'
        if (['db', 'sqlite'].includes(ext)) return 'database'
      }
      return 'file-outline'
    }
    return this.expanded ? 'folder-open-outline' : 'folder-outline'
  }

  get isDir() {
    return this.item.type === 'directory'
  }

  mounted() {
    if (this.depth === 0) {
      this.expanded = true
    }
  }

  @Watch('expanded')
  expand(val) {
    if (val) this.refresh()
    else this.children = []
  }

  open() {
    if (this.isDir) {
      this.expanded = !this.expanded
    } else {
      console.log('todo: open file', this.item.path)
    }
  }

  @Watch('root')
  refresh() {
    this.children = []
    Vue.nextTick(this.ls)
  }

  async ls() {
    this.loading = true
    try {
      const { cwd, items } = await this.$rpc.fs.ls(this.root, this.cwd)
      this.children = items.sort((a: Item, b: Item) => a.type.localeCompare(b.type))
    } finally {
      this.loading = false
    }
  }
}
</script>

<style lang="scss">
.file-tree-list {
  li {
    overflow: hidden;
    white-space: nowrap;
    text-overflow: ellipsis;
    display: block;
  }

  .icon {
    margin-right: 4px;
  }

  span {
    cursor: default;
  }
}
</style>

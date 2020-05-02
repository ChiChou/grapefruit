<template>
  <ul class="file-tree-list">
    <div v-if="item && depth > 0"
      class="name-label"
      :style="{ paddingLeft: depth * 10 + 'px' }"
      :class="{ selected }"
      @click.prevent.stop="select"
    >
      <a v-if="isDir" @click="expanded = !expanded" class="trigger">
        <b-icon v-if="loading" icon="loading" size="is-small" custom-class="mdi-spin" />
        <b-icon v-else :icon="icon" />
      </a>
      <b-icon v-else :icon="icon" />
      <span class="name" @dblclick="open">{{ item.name }}</span>
      <span class="extra" v-if="root === 'home'">
        <a @click="mv(item)"><span class="mdi mdi-rename-box"></span></a>
        <a @click="rm(item)"><span class="mdi mdi-delete"></span></a>
      </span>
    </div>
    <li v-for="(child, index) in children" :key="index">
      <FileTree :root="root" :cwd="cwd + '/' + child.name" :depth="depth + 1" :item="child" />
    </li>
  </ul>
</template>

<script lang="ts">
import { Prop, Component, Watch, Vue } from 'vue-property-decorator'
import { Finder } from '../../interfaces'
import { htmlescape } from '../utils'

@Component({
  name: 'FileTree'
})
export default class FileTree extends Vue {
  private _loading = false

  selected = false
  expanded = false
  children: Finder.Item[] = []
  loading = false

  @Prop({ required: true })
  item!: Finder.Item

  @Prop({ default: 0 })
  depth?: number

  @Prop({ required: true })
  root!: string

  @Prop({ required: true })
  cwd!: string

  get icon() {
    if (this.isDir) return this.expanded ? 'folder-open-outline' : 'folder-outline'

    const { name } = this.item
    const lastIndex = name?.lastIndexOf('.')
    const mapping: { [key: string]: string } = {
      pdf: 'file-pdf-outline',
      js: 'language-javascript',
      plist: 'cog-box',
      dylib: 'cogs',
      xml: 'xml',
      json: 'code-json',
      binarycookies: 'cookie'
    }

    if (lastIndex > -1) {
      const ext = name.substr(lastIndex + 1).toLowerCase()
      if (/^(jpe?g|png|gif)$/.exec(ext)) return 'file-image-outline'
      if (/^html?$/.exec(ext)) return 'language-html5'
      if (/^docx?$/.exec(ext)) return 'file-word-outline'
      if (/^(xlsx?|csv)$/.exec(ext)) return 'file-excel-outline'

      if (Object.prototype.hasOwnProperty.call(mapping, ext)) {
        return mapping[ext]
      }

      if (['txt', 'log'].includes(ext)) return 'file-document-outline'
      if (['wav', 'mp3', 'aac'].includes(ext)) return 'file-music-outline'
      if (['mp4', 'mov', 'avi'].includes(ext)) return 'file-video-outline'
      if (['db', 'sqlite'].includes(ext)) return 'database'
    }

    return 'file-outline'
  }

  get isDir() {
    return this.item.type === 'directory'
  }

  select() {
    this.selected = true
    this.$parent.$emit('select', this)
  }

  dismiss() {
    this.selected = false
  }

  mounted() {
    if (this.depth === 0) {
      this.expanded = true
    }

    this.$on('select', (e: FileTree) => this.$parent.$emit('select', e))
  }

  @Watch('expanded')
  expand(val: boolean) {
    if (val) this.refresh()
    else this.children = []

    // todo: localStorage
  }

  open() {
    if (this.isDir) {
      this.expanded = !this.expanded
    } else {
      console.log('todo: open file', this.item.path)
    }
  }

  // remove file
  rm(item: Finder.Item) {
    const escaped = htmlescape(item.path)

    this.$buefy.dialog.confirm({
      title: 'Removing item',
      message: `Are you sure you want to <strong>delete</strong> the file <code>${escaped}</code>?
        <br>This action cannot be undone.`,
      confirmText: 'Confirm Deletion',
      type: 'is-danger',
      hasIcon: true,
      onConfirm: async() => {
        try {
          await this.$rpc.fs.remove(item.path)
        } catch (e) {
          this.$buefy.toast.open({
            type: 'is-warning',
            message: `Failed to delete ${escaped}. <br>${e}`
          })
          return
        }
        this.$buefy.toast.open(`${item.path} was deleted`)
        this.expanded = false
        if (this.$parent instanceof FileTree) this.$parent.ls()
      }
    })
  }

  mv(item: Finder.Item) {
    const idx = item.path.lastIndexOf('/')
    if (idx === -1) {
      console.error('Invalid path: ', item.path)
      return
    }
    const escaped = htmlescape(item.path)
    const basename = item.path.substr(0, idx + 1)
    console.log(basename, item.path)
    this.$buefy.dialog.prompt({
      message: 'Rename Item',
      inputAttrs: { placeholder: item.name },
      trapFocus: true,
      onConfirm: async(value) => {
        // shall we prevent path traversal here?
        // maybe no? so you can actually move the file to another location
        const dest = basename + value
        try {
          await this.$rpc.fs.move(item.path, dest)
        } catch (e) {
          this.$buefy.toast.open({
            type: 'is-warning',
            message: `Failed to rename ${escaped}. <br>${e}`
          })
          return
        }
        this.$buefy.toast.open(`File has been renamed to ${htmlescape(dest)}`)
        if (this.$parent instanceof FileTree) this.$parent.ls()
      }
    })
  }

  @Watch('root')
  refresh() {
    this.children = []
    Vue.nextTick(this.ls)
  }

  async ls() {
    this.loading = true
    try {
      const { items } = await this.$rpc.fs.ls(this.root, this.cwd)
      this.children = items.sort((a: Finder.Item, b: Finder.Item) => a.type.localeCompare(b.type))
    } finally {
      this.loading = false
    }
  }
}
</script>

<style lang="scss">
.file-tree-list {
  li {
    display: block;
  }

  div.name-label {
    display: flex;
    justify-items: center;
    height: 2rem;
    align-items: center;
    // justify-content: space-between;

    > .extra {
      display: none;

      > a {
        > .mdi {
          font-size: 1.5rem;
        }

        color: #888;
        display: inline-block;
        text-align: center;
        width: 2rem;
        border-radius: 2px;

        &:hover {
          background: #000;
          color: #bbb;
        }
      }
    }

    &.selected {
      background: #1f1f1f;

      > .extra {
        display: inline;
      }
    }

    > a .icon {
      cursor: pointer;
    }

    .icon {
      margin-right: 0.5rem;
    }

    > span.name {
      flex: 1;
      min-width: 0;
      overflow: hidden;
      cursor: default;
      white-space: nowrap;
      text-overflow: ellipsis;
    }
  }

}
</style>

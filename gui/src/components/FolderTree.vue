<template>
  <!-- todo: drag drop to folder -->
  <article>
    <div v-if="item && depth > 0"
      class="name-label"
      :style="{ paddingLeft: depth * 10 + 'px' }"
      :class="{ selected }"
      @click.prevent.stop="select"
    >
      <a @click="expanded = !expanded" class="trigger">
        <b-icon v-if="loading" icon="loading" size="is-small" custom-class="mdi-spin" />
        <b-icon v-else :icon="icon" />
      </a>
      <span class="name" @dblclick="dblclick">{{ item.name }}</span>
      <span class="extra">
        <span v-if="root === 'home'">
          <a @click="mv"><span class="mdi mdi-rename-box"></span></a>
          <a @click="rm"><span class="mdi mdi-delete"></span></a>
        </span>
        <a @click="download" v-if="item.type === 'file'">
          <span class="mdi mdi-download is-danger"></span>
        </a>
        <a @click="open" v-if="item.type === 'file'">
          <span class="mdi mdi-open-in-new"></span>
        </a>
      </span>
    </div>
    <ul
      v-if="children.length"
      class="file-tree-list"
      @dragover.prevent.stop="dragover"
      @dragleave.prevent.stop="dragleave"
      @drop.prevent.stop="drop"
      :class="{ dropping }"
    >
      <li v-for="(child, index) in children" :key="index">
        <FileTree :loading.sync="loading" :root="root" :cwd="cwd + '/' + child.name" :depth="depth + 1" :item="child" />
      </li>
    </ul>
  </article>
</template>

<script lang="ts">
import { FinderModule } from '@/store/modules/finder'
import { Prop, Component, Watch, Vue } from 'vue-property-decorator'
import { Finder } from '@/interfaces'
import { htmlescape } from '@/utils'

@Component({ name: 'FileTree' })
export default class FileTree extends Vue {
  private _loading = false

  get loading() {
    return this._loading
  }

  set loading(val: boolean) {
    this._loading = val
    this.$emit('update:loading', val)
  }

  selected = false
  expanded = false
  children: Finder.Item[] = []
  dropping = false

  @Prop({ required: true })
  item!: Finder.Item

  @Prop({ default: 0 })
  depth!: number

  @Prop({ required: true })
  root!: string

  @Prop({ required: true })
  cwd!: string

  get icon() {
    return this.expanded ? 'folder-open-outline' : 'folder-outline'
  }

  select() {
    this.selected = true
    this.$parent.$emit('select', this)

    this.$bus.$emit('switchTab', 'Finder', 'Finder')
    FinderModule.cd(this.cwd)
  }

  dismiss() {
    this.selected = false
  }

  mounted() {
    if (this.depth === 0) {
      this.expanded = true
    }

    this.$on('select', (e: FileTree) => this.$parent.$emit('select', e))
    // this.$on('update:loading', (val: boolean) => this.$parent.$emit('update:loading', val))
  }

  @Watch('expanded')
  expand(val: boolean) {
    if (val) this.refresh()
    else this.children = []

    // todo: localStorage
  }

  dblclick() {
    this.expanded = !this.expanded
  }

  dragover() {
    this.dropping = true
  }

  dragleave() {
    this.dropping = false
  }

  drop() {
    this.dropping = false
  }

  // remove file
  rm() {
    const { path } = this.item
    const escaped = htmlescape(path)

    this.$buefy.dialog.confirm({
      title: 'Removing item',
      message: `Are you sure you want to <strong>delete</strong> the file <code>${escaped}</code>?
        <br>This action cannot be undone.`,
      confirmText: 'Confirm Deletion',
      type: 'is-danger',
      hasIcon: true,
      onConfirm: async() => {
        try {
          await this.$rpc.fs.remove(path)
        } catch (e) {
          this.$buefy.toast.open({
            type: 'is-warning',
            message: `Failed to delete ${escaped}. <br>${e}`
          })
          return
        }
        this.$buefy.toast.open(`${path} has been deleted`)
        this.expanded = false
        if (this.$parent instanceof FileTree) this.$parent.ls()
      }
    })
  }

  mv() {
    const { path, name } = this.item
    const idx = path.lastIndexOf('/')
    if (idx === -1) return
    const escaped = htmlescape(path)
    const basename = path.substr(0, idx + 1)
    this.$buefy.dialog.prompt({
      message: 'Rename Item',
      inputAttrs: { placeholder: name },
      trapFocus: true,
      onConfirm: async(value) => {
        // shall we prevent path traversal here?
        // maybe no? so you can actually move the file to another location
        const dest = basename + value
        try {
          await this.$rpc.fs.move(path, dest)
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
      const { items } = await this.$rpc.fs.subdirs(this.root, this.cwd)
      this.children = items.sort((a: Finder.Item, b: Finder.Item) => a.type.localeCompare(b.type))
    } finally {
      this.loading = false
    }
  }
}
</script>

<style lang="scss">
.file-tree-list {
  &.dropping {
    background: #009688;

    div.name-label.selected{
      background: #009688;
    }
  }

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

      > a, > span > a {
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

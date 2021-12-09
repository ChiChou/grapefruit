<template>
  <div>
    <nav class="breadcrumb nav-bar level-left" aria-label="breadcrumbs">
      <ul class="level-item">
        <li class="root-indicator">
          <a @click="up(0)" title="Home" v-if="root === 'home'">
            <b-icon icon="folder-home-outline"></b-icon> <span>Data</span>
          </a>
          <a @click="up(0)" title="App Bundle" v-if="root === 'bundle'">
            <b-icon icon="folder-cog-outline"></b-icon> <span>App Bundle</span>
          </a>
        </li>
        <li v-for="(name, idx) in components" :key="name">
          <a @click="up(idx + 1)">
            <b-icon icon="folder"></b-icon>
            <span>{{ name }}</span>
          </a>
        </li>
      </ul>
    </nav>

    <main class="finder-row">
      <article class="file-list">
        <b-table
          class="fixed finder"
          :data="list"
          narrowed
          :loading="loading"
          default-sort="type"
          :selected.sync="selected"
        >
          <template slot-scope="props">
            <b-table-column field="type" sortable>
              <b-icon icon="folder" v-if="props.row.type == 'directory'" />
              <b-icon :icon="icon(props.row)" v-else />
            </b-table-column>

            <b-table-column field="name" label="Name" sortable class="ellipsis">
              <a class="filename" @click="open(props.row)">
                <span> {{ props.row.name }}</span>
              </a>
            </b-table-column>

            <b-table-column field="owner" label="Owner" sortable width="120">
              {{ props.row.attribute.owner }}
            </b-table-column>

            <b-table-column
              field="protection"
              label="Protection"
              sortable
              width="240"
              class="ellipsis"
            >
              <span :title="props.row.attribute.protection">{{
                props.row.attribute.protection
              }}</span>
            </b-table-column>

            <b-table-column
              field="size"
              label="Size"
              class="monospace ellipsis"
              sortable
              width="120"
            >
              {{ readableSize(props.row.attribute.size) }}
            </b-table-column>
          </template>
        </b-table>
      </article>

      <aside class="detail" v-if="selected">
        <p class="path">{{ selected.path }}</p>
        <p>
          {{ perm(selected.attribute.permission) }}
          {{ selected.attribute.owner }}:{{ selected.attribute.group }}
        </p>

        <p>{{ selected.attribute.type }}</p>

        <p>Created: {{ selected.attribute.creation }}</p>
        <p>Modified: {{ selected.attribute.modification }}</p>
        <p>Protection: {{ selected.attribute.protection }}</p>

        <nav class="file-op">
          <b-field>
            <p class="control" v-if="selected.type === 'file'">
              <b-button @click="open(selected)" icon-left="open-in-new" />
            </p>
            <p class="control" v-if="selected.type === 'file'">
              <b-button @click="download(selected)" icon-left="download" />
            </p>
            <p class="control" v-if="root === 'home'">
              <b-button @click="mv(selected)" icon-left="rename-box" title="Rename" />
            </p>
            <p class="control" v-if="root === 'home'">
              <b-button type="is-danger" @click="rm(selected)" icon-left="delete" title="Delete" />
            </p>
          </b-field>
        </nav>
      </aside>
    </main>
  </div>
</template>

<script lang="ts">
import { Component, Watch } from 'vue-property-decorator'
import { Finder } from '@/interfaces'
import { FinderModule } from '@/store/modules/finder'
import { filetype, htmlescape, humanFileSize, icon } from '@/utils'
import { Root } from '@/store/types'
import Base from './Base.vue'

@Component
export default class FinderTab extends Base {
  list: Finder.Item[] = []
  selected: Finder.Item | null = null

  get cwd(): string {
    return FinderModule.path
  }

  get root(): Root {
    return FinderModule.root
  }

  get perm() {
    return (val: number) => val.toString(8)
  }

  get readableSize() {
    return (val: number) => humanFileSize(val)
  }

  get icon() {
    return (item: Finder.Item) => icon(item.name)
  }

  get components(): string[] {
    let path = this.cwd
    if (!path || typeof path !== 'string') return []
    path = path.replace(/^\/+/, '')
    return path.split('/')
  }

  mounted() {
    this.ls()
  }

  goHome() {
    FinderModule.goHome()
  }

  goApp() {
    FinderModule.goApp()
  }

  up(level: number) {
    if (level === 0) {
      FinderModule.cd('')
      return
    }
    const path = this.components.slice(0, level).join('/')
    FinderModule.cd(path)
  }

  @Watch('cwd')
  @Watch('root')
  async onChangeDir() {
    this.ls()
  }

  open(item: Finder.Item) {
    if (!item) return
    if (item.type === 'directory') {
      FinderModule.cd(`${this.cwd}/${item.name}`)
      return
    }

    const t = filetype(item.name)
    const mapping: { [key: string]: string } = {
      audio: 'MediaPreview',
      video: 'MediaPreview',
      json: 'DictPreview',
      plist: 'DictPreview',
      image: 'ImagePreview',
      pdf: 'PDFPreview',
      text: 'TextPreview',
      cookiejar: 'Cookies',
      database: 'SQLitePreview',
      // todo: hex:
    }
    const viewer = mapping[t] || 'UnknownPreview'
    this.$bus.$emit('openTab', viewer, `Preview - ${item.name}`, {
      path: item.path,
    })
  }

  async download(item: Finder.Item) {
    const token = await this.$rpc.fs.download(item.path)
    location.replace(`/api/download/${token}`)
  }

  // todo: clean duplicated code
  mv(item: Finder.Item) {
    const { path, name } = item
    const idx = path.lastIndexOf('/')
    if (idx === -1) return
    const escaped = htmlescape(path)
    const basename = path.substr(0, idx + 1)
    this.$buefy.dialog.prompt({
      message: 'Rename Item',
      inputAttrs: { placeholder: name },
      trapFocus: true,
      onConfirm: async(value) => {
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
        this.ls()
      }
    })
  }

  rm(item: Finder.Item) {
    const { path } = item
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
        this.ls()
      }
    })
  }

  async ls() {
    this.loading = true
    try {
      const { items } = await this.$rpc.fs.ls(this.root, this.cwd)
      this.list = items.sort((a: Finder.Item, b: Finder.Item) =>
        a.type.localeCompare(b.type)
      )
    } finally {
      this.loading = false
    }
    this.selected = null
  }
}
</script>

<style lang="scss" scoped>
.breadcrumb.nav-bar {
  padding: 10px;
}

.finder-row {
  display: flex;
  flex-direction: row;

  .file-list {
    flex: 1;
  }

  aside.detail {
    width: 320px;
    padding: 10px;
    overflow-y: hidden;
    word-break: break-all;
  }
}
</style>
<template>
  <div>
    <b-progress class="thin" :class="{ show: loading }"></b-progress>
    <header>
      <h1>WebView &amp; JavaScript</h1>
      <nav>
        <a @click="refresh"><b-icon icon="refresh" /></a>
      </nav>
    </header>

    <aside class="menu" :class="{ loading }">
      <p class="menu-label">WK</p>
      <ul class="menu-list">
        <li v-for="(title, handle) in this.WK" :key="handle" @click="open(handle, title)">
          <b-icon icon="web-box" />{{ title }}
        </li>
      </ul>
      <p class="menu-label">UI</p>
      <ul class="menu-list">
        <li v-for="(title, handle) in this.UI" :key="handle" @click="open(handle, title)">
          <b-icon icon="web-box" />{{ title }}
        </li>
      </ul>
      <p class="menu-label">JSContext</p>
      <ul class="menu-list">
        <li v-for="(description, handle) in this.jsc" :key="handle" @click="jsContext(handle)">
          <b-icon icon="language-javascript" />{{ description }}
        </li>
      </ul>
    </aside>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'

@Component
export default class WebViews extends Vue {
  loading = false

  WK = {}
  UI = {}
  jsc = {}

  mounted() {
    this.refresh()
  }

  open(handle: string, title: string) {
    this.$bus.$emit('openTab', 'WebViewDetail', 'WebView - ' + title, { handle })
  }

  jsContext(handle: string) {
    this.$bus.$emit('openTab', 'JSCDetail', 'JSContext - ' + handle, { handle })
  }

  async refresh() {
    this.loading = true
    try {
      const { WK, UI } = await this.$rpc.webview.list()
      this.WK = WK
      this.UI = UI
      this.jsc = await this.$rpc.jsc.list()
    } finally {
      this.loading = false
    }
  }
}

</script>

<style lang="scss" scoped>
header {
  display: flex;

  h1 {
    flex: 1;
    padding: .5em;
  }

  nav {
    padding: .5em;

    > a {
      color: #999;
      &:hover {
        color: #fff;
      }
    }
  }
}

.menu {
  padding: 10px;

  &.loading {
    display: none;
  }
}

.menu-list li {
  padding: 6px 12px;
  cursor: pointer;
  background: transparent;
  color: #aaa;
  transition: ease-in 0.2s background-color, color;
  text-shadow: 1px 1px 2px #00000030;
  text-overflow: ellipsis;
  overflow: hidden;
  white-space: nowrap;

  .icon {
    margin-right: 8px;
  }

  &:hover {
    background: #00000030;
    color: #fff;
  }
}
</style>

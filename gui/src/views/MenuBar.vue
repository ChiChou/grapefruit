<template>
  <menu>
    <themed-menu class="menu">
      <hsc-menu-bar>
        <hsc-menu-bar-item label="🍎">
          <hsc-menu-item label="About" />
          <hsc-menu-separator />
          <hsc-menu-item label="Disconnect Sesssion" @click="$router.push({ name: 'Apps', params: { device: $route.params.device }})"/>
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="File">
          <hsc-menu-item label="New REPL" />
          <hsc-menu-separator />
          <hsc-menu-item label="Open Snippet" />
          <hsc-menu-item label="Import Snippet" />
          <hsc-menu-separator />
          <hsc-menu-item label="Save Snippet" keybind="meta+s" />
          <hsc-menu-item label="Export Snippet" />
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="Logs">
          <hsc-menu-item label="Export" />
          <hsc-menu-item label="Search" />
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="Help">
          <hsc-menu-item label="GitHub Repo" @click="external('https://github.com/')"/>
          <hsc-menu-item label="Documentation" @click="external('https://github.com/')"/>
          <hsc-menu-separator />
          <hsc-menu-item label="Check NPM Updates" @click="update()"/>
        </hsc-menu-bar-item>
      </hsc-menu-bar>
    </themed-menu>
  </menu>
</template>

<script lang="ts">
import { StyleFactory } from '@hscmap/vue-menu'
import { Component, Vue } from 'vue-property-decorator'

@Component({
  components: {
    'themed-menu': StyleFactory({
      menu: {
        borderRadius: '2px',
        fontWeight: '100',
        background: '#1e1e1e',
        boxShadow: '2px 2px 2px rgba(0, 0, 0, 0.3)'
      },
      menubar: {
        background: '#222',
        color: '#c1c1c1'
      },
      active: {
        backgroundColor: '#505050',
        zIndex: '99999'
      },
      disabled: {
        opacity: '0.5'
      },
      separator: {
        backgroundColor: '#333'
      },
      animation: false
    })
  }
})
export default class MenuBar extends Vue {
  external(url: string) {
    window.open(url, '_blank')
  }

  update() {
    // todo
  }
}
</script>

<style lang="scss" scoped>
menu {
  z-index: 999999;
  padding: 0;
  margin: 0;
  background: #222;

  .menubaritem {
    padding-left: 10px !important;
    padding-right: 10px !important;
  }

  .label {
    font-weight: 100 !important;
  }

  .label:not(:last-child) {
    margin-bottom: 4px !important;
  }

  .menuitem {
    font-weight: 100;
  }
}

h1 {
  display: block;
  float: left;
  line-height: 36px;
  margin: 0 10px;
  font-weight: 100;
}
</style>

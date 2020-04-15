<template>
  <menu>
    <themed-menu class="menu">
      <hsc-menu-bar>
        <hsc-menu-bar-item label="🍎">
          <hsc-menu-item label="About" />
          <hsc-menu-separator />
          <hsc-menu-item label="GitHub" />
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="File">
          <hsc-menu-item label="New" />
          <hsc-menu-item label="Open" />
          <hsc-menu-separator />
          <hsc-menu-item label="Save" :disabled="true" />
          <hsc-menu-item label="Export to">
            <hsc-menu-item label="PDF" />
            <hsc-menu-item label="HTML" />
          </hsc-menu-item>
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="Edit">
          <hsc-menu-item label="Undo" keybind="meta+z" />
          <hsc-menu-separator />
          <hsc-menu-item label="Cut" keybind="meta+x" />
          <hsc-menu-item label="Copy" keybind="meta+c" />
          <hsc-menu-item label="Paste" keybind="meta+v" :disabled="true" />
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
export default class MenuBar extends Vue {}
</script>

<style lang="scss" scoped>
menu {
  z-index: 999999;
  padding: 0;
  margin: 0;
  background: #222;

  .label {
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

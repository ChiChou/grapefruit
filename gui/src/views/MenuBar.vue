<template>
  <menu>
    <h1 @dblclick="external('https://www.youtube.com/watch?v=dQw4w9WgXcQ')">
      <img src="../assets/logo.svg" width="100">
    </h1>
    <themed-menu class="menu">
      <hsc-menu-bar>
        <hsc-menu-bar-item label="Session">
          <hsc-menu-item label="Reload" @click="reload" />
          <hsc-menu-item label="Detach" @click="detach" />
          <hsc-menu-separator />
          <hsc-menu-item label="Kill" @click="kill" />
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="Layout">
          <hsc-menu-item label="Reset" @click="reset"/>
        </hsc-menu-bar-item>
        <!-- <hsc-menu-bar-item label="Snippet">
          <hsc-menu-item label="New REPL" />
          <hsc-menu-separator />
          <hsc-menu-item label="Open Snippet" />
          <hsc-menu-item label="Import Snippet" />
          <hsc-menu-separator />
          <hsc-menu-item label="Save Snippet" keybind="meta+s" />
          <hsc-menu-item label="Export Snippet" />
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="Log">
          <hsc-menu-item label="Export" />
          <hsc-menu-item label="Search" />
        </hsc-menu-bar-item> -->
        <hsc-menu-bar-item label="Help">
          <hsc-menu-item label="About" @click="isAboutDialogActive = true" />
          <hsc-menu-separator />
          <hsc-menu-item label="GitHub Repo" @click="external('https://github.com/chichou/grapefruit')" />
          <hsc-menu-item label="Support Me on Patreon" @click="external('https://www.patreon.com/codecolorist')" />
          <!-- <hsc-menu-separator />
        <hsc-menu-item label="Check NPM Updates" @click="update()" /> -->
        </hsc-menu-bar-item>
      </hsc-menu-bar>
    </themed-menu>

    <b-modal :active.sync="isAboutDialogActive" :width="480" scroll="keep">
      <div class="card has-text-centered">
        <div class="card-image">
          <img src="../assets/logo.svg" alt="Grapefruit" class="image" width="300" style="margin: 40px auto" />
        </div>
        <div class="card-content">
          <h2>Grapefruit @{{ version }}</h2>
          <p>Runtime Application Instruments for iOS</p>
          <hr>
          <p>Brought to you by <a href="https://twitter.com/codecolorist" target="_blank">@CodeColorist</a></p>
          <p>Built on <a href="https://vuejs.org/" target="_blank">Vue.js</a>,
            <a href="https://frida.re/" target="_blank">frida</a>
            and <a href="https://buefy.org/" target="_blanl">Buefy</a></p>
        </div>
      </div>
    </b-modal>
  </menu>
</template>

<script lang="ts">
import pkg from '../../../package.json'

import Axios from 'axios'
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
  isAboutDialogActive = false
  version = pkg.version

  external(url: string) {
    window.open(url, '_blank')
  }

  reload() {
    location.reload()
  }

  kill() {
    this.$ws.send('kill')
    this.detach()
  }

  reset() {
    localStorage.removeItem('layout-state')
    location.reload()
  }

  detach() {
    this.$router.push({
      name: 'Apps',
      params: { device: this.$route.params.device }
    })
  }

  update() {
    Axios.get('/update').then(({ data }) => {
      const { current, latest } = data
      if (current !== latest) {
        this.$buefy.dialog.alert({
          hasIcon: true,
          icon: 'update',
          type: 'is-success',
          title: 'New version found',
          message: `Newer version ${latest} found. You are on ${current}.
For the limitation of web app, we don't provide automate update.<br>
Please run <code>npm install -g passionfruit@${latest}</code> in your terminal manually.`
        })
      }
    })
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
  margin: 8px 2px 2px 16px;
  font-weight: 100;
}
</style>

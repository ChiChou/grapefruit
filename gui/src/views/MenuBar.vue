<template>
  <menu>
    <h1 @dblclick="external('https://www.youtube.com/watch?v=dQw4w9WgXcQ')">
      <img src="../assets/grapefruit.svg" width="20">
    </h1>
    <themed-menu class="menu">
      <hsc-menu-bar>
        <hsc-menu-bar-item label="General">
          <hsc-menu-item label="Basic" @click="go('Info')"/>
          <hsc-menu-item label="CheckSec" @click="go('CheckSec')"/>
          <hsc-menu-item label="URL Schemes" @click="go('Url', 'URL Schemes')"/>
          <hsc-menu-separator />
          <hsc-menu-item label="Cookies" @click="go('Cookies')"/>
          <hsc-menu-item label="KeyChain" @click="go('KeyChain')"/>
          <hsc-menu-item label="NSUserDefaults" @click="go('UserDefaults')"/>
          <hsc-menu-separator />
          <hsc-menu-item label="UIDump" @click="open('UIDump')"/>
          <hsc-menu-item label="Privacy" @click="go('Privacy')"/>
          <hsc-menu-separator />
          <hsc-menu-item label="GPS Simulator" @click="go('GeoLocation')"/>
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="Finder">
          <hsc-menu-item label="Home" @click="finder('home')"/>
          <hsc-menu-item label="Bundle" @click="finder('bundle')"/>
        </hsc-menu-bar-item>
        <hsc-menu-bar-item label="View">
          <hsc-menu-item label="Process Modules" @click="redirect({ name: 'Modules' })"/>
          <hsc-menu-item label="Runtime Classes" @click="redirect({ name: 'Classes' })"/>
          <hsc-menu-separator />
          <hsc-menu-item label="Search API" @click="redirect({ name: 'Api Resolver' })"/>
          <hsc-menu-separator />
          <hsc-menu-item label="REPL" @click="redirect({ name: 'REPL' })"/>
          <hsc-menu-separator />
          <hsc-menu-item label="WebViews and JavascriptCore" @click="redirect({ name: 'WebViews' })"/>
        </hsc-menu-bar-item>
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
          <hsc-menu-item label="GitHub Repo" @click="external('https://github.com/chichou/grapefruit')" />
          <hsc-menu-separator />
          <hsc-menu-item label="Support Me on Patreon" @click="external('https://www.patreon.com/codecolorist')" />
          <hsc-menu-item label="Donate on PayPal" @click="external('https://www.paypal.com/paypalme/codecolorist')" />
          <!-- <hsc-menu-separator />
        <hsc-menu-item label="Check NPM Updates" @click="update()" /> -->
        </hsc-menu-bar-item>
      </hsc-menu-bar>
    </themed-menu>

    <b-modal :active.sync="isAboutDialogActive" :width="480" scroll="keep">
      <div class="card has-text-centered">
        <div class="card-image">
          <img src="../assets/logo.svg" alt="Grapefruit" class="image" width="300" height="60" style="margin: 40px auto" />
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
import router from '@/router'
import { FinderModule } from '@/store/modules/finder'
import { RawLocation } from 'vue-router'

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

  redirect(url: RawLocation) {
    router.push(url).catch((_) => {})
  }

  finder(dest: string) {
    this.redirect({ name: 'Files' })

    if (dest === 'home') {
      FinderModule.goHome()
    } else if (dest === 'bundle') {
      FinderModule.goApp()
    } else {
      throw new Error('invalid destination: ' + dest)
    }
    this.$bus.$emit('switchTab', 'Finder', 'Finder')
  }

  open(component: string, title?: string, props?: object) {
    this.$bus.$emit('openTab', component, title || component, props)
  }

  go(component: string, title?: string, props?: object) {
    this.$bus.$emit('switchTab', component, title || component, props)
  }

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
  margin: 8px 16px 2px 24px;
  font-weight: 100;
}
</style>

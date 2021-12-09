<template>
  <aside class="menu">
    <p class="menu-label">General</p>
    <ul class="menu-list">
      <li @click="go('Info')">
        <b-icon icon="information-outline" />Basic
      </li>
      <li @click="go('CheckSec')">
        <b-icon icon="briefcase-check" />CheckSec
      </li>
      <li @click="go('Url', 'URL Schemes')">
        <b-icon icon="link-variant" />URL Schemes
      </li>
    </ul>

    <p class="menu-label">Storage</p>
    <ul class="menu-list">
      <li @click="go('Cookies')">
        <b-icon icon="cookie" />Cookies
      </li>
      <li @click="go('KeyChain')">
        <b-icon icon="folder-key-outline" />KeyChain
      </li>
      <li @click="go('UserDefaults')">
        <b-icon icon="card-bulleted-outline" />NSUserDefaults
      </li>
    </ul>

    <p class="menu-label">Inspector</p>
    <ul class="menu-list">
      <li @click="open('UIDump')">
        <b-icon icon="magnify-scan" />UI Dump
      </li>
      <li @click="go('Privacy')">
        <b-icon icon="lock" />Privacy
      </li>
    </ul>

    <p class="menu-label">Simulate</p>
    <ul class="menu-list">
      <li @click="go('GeoLocation')">
        <b-icon icon="earth" />GPS
      </li>
    </ul>
  </aside>
</template>

<script lang="ts">

import { Component, Vue } from 'vue-property-decorator'

@Component
export default class General extends Vue {
  open(component: string, title?: string, props?: object) {
    this.$bus.$emit('openTab', component, title || component, props)
  }

  go(component: string, title?: string, props?: object) {
    this.$bus.$emit('switchTab', component, title || component, props)
  }
}
</script>

<style lang="scss" scoped>
.menu {
  padding: 20px;
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

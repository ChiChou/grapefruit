<template>
  <aside class="menu">
    <p class="menu-label">General</p>
    <ul class="menu-list">
      <li @click="open('CheckSec')">
        <b-icon icon="briefcase-check" />CheckSec
      </li>
      <li @click="open('Url')">
        <b-icon icon="link-variant" />URL Schemes
      </li>
      <li @click="open('Info', {})">
        <b-icon icon="information-outline" />Info PList
      </li>
    </ul>

    <p class="menu-label">Storage</p>
    <ul class="menu-list">
      <li>
        <b-icon icon="cookie" />Cookies
      </li>
      <li>
        <b-icon icon="folder-key-outline" />KeyChain
      </li>
      <li>
        <b-icon icon="card-bulleted-outline" />NSUserDefaults
      </li>
    </ul>

    <p class="menu-label">Inspector</p>
    <ul class="menu-list">
      <li>
        <b-icon icon="camera" />ScreenShot
      </li>
      <li>
        <b-icon icon="magnify-scan" />UI Dump
      </li>
    </ul>
  </aside>
</template>

<script lang="ts">

import { Component, Vue } from 'vue-property-decorator'

@Component
export default class MenuBar extends Vue {
  open(component: string, props?: object) {
    this.$root.$emit('openTab', component, props)
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

  .icon {
    margin-right: 8px;
  }

  &:hover {
    background: #00000030;
    color: #fff;
  }
}
</style>

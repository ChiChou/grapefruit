<template>
  <aside class="menu">
    <p class="menu-label">General</p>
    <ul class="menu-list">
      <li><a @click="go('BasicInfo', 'Basic')"><n-icon :component="InfoOutlined" />Basic</a></li>
      <li><a @click="go('CheckSec', 'CheckSec')"><n-icon :component="SecurityFilled" />CheckSec</a></li>
      <li><a @click="go('URLPage', 'URL Tester')"><n-icon :component="LinkRound" />URL Schemes</a></li>      
    </ul>

    <p class="menu-label">Storage</p>
    <ul class="menu-list">
      <li><a @click="go('BasicInfo', 'Cookies')"><n-icon :component="CookieOutlined" />Cookies</a></li>
      <li><a @click="go('BasicInfo', 'KeyChain')"><n-icon :component="KeyFilled" />KeyChain</a></li>
      <li><a @click="go('BasicInfo', 'User Preferences')"><n-icon :component="RoomPreferencesOutlined" />NSUserDefaults</a></li>
    </ul>

    <p class="menu-label">Inspector</p>
    <ul class="menu-list">
      <li><a @click="go('BasicInfo')"><n-icon :component="CursorHover16Regular" />UI Dump</a></li>
      <li><a @click="go('BasicInfo')"><n-icon :component="PrivacyTipOutlined" />Privacy</a></li>
    </ul>

    <p class="menu-label">Simulate</p>
    <ul class="menu-list">
      <li><a @click="go('BasicInfo')"><n-icon :component="MapPin" />GPS</a></li>
    </ul>
  </aside>
</template>

<script lang="ts" setup>
import {
  InfoOutlined,
  SecurityFilled,
  LinkRound,
  CookieOutlined,
  KeyFilled,
  RoomPreferencesOutlined,
  PrivacyTipOutlined,
} from '@vicons/material'

import {
  MapPin
} from '@vicons/tabler'

import {
  CursorHover16Regular
} from '@vicons/fluent'

import { inject } from 'vue'
import { CREATE_TAB } from '@/types'

const createTab = inject(CREATE_TAB)!

function go(tab: string, title: string='', state?: any) {
  createTab(tab, title, state, false);
}

</script>

<style scoped>
.menu-list a {
  cursor: pointer;
}
</style>
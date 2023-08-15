<template>
  <aside class="menu">
    <p class="menu-label">General</p>
    <ul class="menu-list">
      <li>
        <a @click="go('BasicInfo')"><n-icon :component="InfoOutlined" />Basic</a>
      </li>
      <li>
        <a @click="go('BasicInfo')"><n-icon :component="LinkRound" />URL Schemes</a>
      </li>
      <li>
        <a @click="go('InfoPropertyList')"><n-icon :component="SearchInfo20Regular" />Info.plist</a>
      </li>
      <li>
        <a @click="go('Entitlements')"><n-icon :component="SecurityFilled" />Entitlements</a>
      </li>
    </ul>

    <p class="menu-label">Storage</p>
    <ul class="menu-list">
      <li><a @click="go('BasicInfo')"><n-icon :component="CookieOutlined" />Cookies</a></li>
      <li><a @click="go('BasicInfo')"><n-icon :component="KeyFilled" />KeyChain</a></li>
      <li><a @click="go('UserDefaults')"><n-icon :component="RoomPreferencesOutlined" />NSUserDefaults</a></li>
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
  CursorHover16Regular,
  SearchInfo20Regular,
} from '@vicons/fluent'

import { useTabNavigator } from '@/plugins/tab'

const { go } = useTabNavigator()

</script>

<style scoped>
.menu-list a {
  cursor: pointer;
}
</style>
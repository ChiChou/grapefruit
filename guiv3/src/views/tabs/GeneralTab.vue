<template>
  <aside class="menu">
    <p class="menu-label">General</p>
    <ul class="menu-list">
      <li>
        <router-link to="general">
          <n-icon :component="InfoOutlined" />Basic
        </router-link>
      </li>
      <li>
        <router-link to="general">
          <n-icon :component="SecurityFilled" />CheckSec
        </router-link>
      </li>
      <li>
        <router-link to="general">
          <n-icon :component="LinkRound" />URL Schemes
        </router-link>
      </li>
    </ul>

    <p class="menu-label">Storage</p>
    <ul class="menu-list">
      <li>
        <router-link to="general">
          <n-icon :component="CookieOutlined" />Cookies
        </router-link>
      </li>
      <li>
        <router-link to="general">
          <n-icon :component="KeyFilled" />KeyChain
        </router-link>
      </li>
      <li>
        <router-link to="general">
          <n-icon :component="RoomPreferencesOutlined" />NSUserDefaults
        </router-link>
      </li>
    </ul>

    <p class="menu-label">Inspector</p>
    <ul class="menu-list">
      <li>
        <router-link to="general">
          <n-icon :component="CursorHover16Regular" />UI Dump
        </router-link>
      </li>
      <li>
        <router-link to="general">
          <n-icon :component="PrivacyTipOutlined" />Privacy
        </router-link>
      </li>
    </ul>

    <p class="menu-label">Simulate</p>
    <ul class="menu-list">
      <li>
        <router-link to="general">
          <n-icon :component="MapPin" />GPS
        </router-link>
      </li>
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
</script>

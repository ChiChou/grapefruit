<script setup lang="ts">
import { Component, h, ref } from 'vue'
import { NIcon } from 'naive-ui'
import {
  AppsOutlined,
  MenuFilled,
  InfoOutlined,
  SecurityFilled,
  LinkFilled,
  HelpCenterOutlined,
  CookieOutlined,
  KeyRound,
  SettingsOutlined,
  AccountTreeOutlined,
  PrivacyTipOutlined,
  GpsFixedOutlined,
  FolderOpenFilled,
  RefreshOutlined,
  ListAltOutlined,
  JavascriptOutlined,
  StopFilled,
  ViewColumnOutlined,
  ViewQuiltSharp,
  ViewModuleSharp,
  HomeSharp,
} from '@vicons/material'

import type { MenuOption } from 'naive-ui'

function renderIcon(icon: Component) {
  return () => h(NIcon, null, { default: () => h(icon) })
}

const menuOptions: MenuOption[] = [
  {
    label: 'General',
    key: 'general',
    icon: renderIcon(AppsOutlined),
    children: [
      {
        type: 'group',
        label: 'Info',
        key: 'info',
        children: [
          {
            label: 'Basic',
            key: 'basic',
            icon: renderIcon(InfoOutlined),
          },
          {
            label: 'CheckSec',
            key: 'checksec',
            icon: renderIcon(SecurityFilled),
          },
          {
            label: 'URL Schemes',
            key: 'urlschemes',
            icon: renderIcon(LinkFilled),
          }
        ]
      },
      {
        type: 'group',
        label: 'Persistence',
        key: 'persistence',
        children: [
          {
            label: 'Cookies',
            key: 'cookies',
            icon: renderIcon(CookieOutlined),
          },
          {
            label: 'KeyChain',
            key: 'keychain',
            icon: renderIcon(KeyRound),
          },
          {
            label: 'NSUserDefaults',
            key: 'nsuserdefaults',
            icon: renderIcon(SettingsOutlined),
          }
        ]
      },
      {
        type: 'group',
        label: 'Misc',
        children: [
          {
            label: 'UIDump',
            key: 'uidump',
            icon: renderIcon(AccountTreeOutlined),
          },
          {
            label: 'Privacy Report',
            key: 'privacy',
            icon: renderIcon(PrivacyTipOutlined),
          },
          {
            label: 'GPS Simulator',
            key: 'gps',
            icon: renderIcon(GpsFixedOutlined),
          }
        ]
      }
    ]
  },
  {
    label: 'Finder',
    key: 'finder',
    icon: renderIcon(FolderOpenFilled),
    children: [
      {
        label: 'Home',
        key: 'home',
        icon: renderIcon(HomeSharp),
      },
      {
        label: 'Bundle',
        key: 'bundle',
      }
    ],
  },
  {
    label: 'View',
    key: 'view',
    icon: renderIcon(ViewColumnOutlined),
    children: [
      {
        label: 'Frameworks',
        key: 'frameworks',
        icon: renderIcon(ListAltOutlined),
      },
      {
        label: 'Runtime Classes',
        key: 'classes'
      },
      {
        label: 'API Resolver',
        key: 'api-resolver',
      },
      {
        label: 'REPL',
        key: 'repl',
      },
      {
        label: 'WebView and JavaScriptCore',
        key: 'webview',
        icon: renderIcon(JavascriptOutlined),
      }
    ]
  },
  {
    label: 'Session',
    key: 'session',
    children: [
      {
        label: 'Reload',
        key: 'reload',
        icon: renderIcon(RefreshOutlined),
      },
      {
        label: () =>
          h(
            'a',
            {
              href: '/',
            },
            'Detach'
          ),
        key: 'detach'
      },
      {
        type: 'divider',
      },
      {
        label: 'Kill',
        key: 'kill',
        icon: renderIcon(StopFilled),
      },
    ]
  },
  {
    label: 'Layout',
    key: 'layout',
    icon: renderIcon(ViewQuiltSharp),
    children: [
      {
        label: 'Reset',
        key: 'reset',
      }
    ]
  },
  {
    label: 'Help',
    key: 'help',
    icon: renderIcon(HelpCenterOutlined),
    children: [
      {
        label: 'About',
        key: 'about'
      },
      {
        type: 'divider'
      },
      {
        label: () =>
          h(
            'a',
            {
              href: 'https://github.com/chichou/grapefruit',
              target: '_blank',
              rel: 'noopenner noreferrer'
            },
            'GitHub'
          ),
      },
      {
        label: () =>
          h(
            'a',
            {
              href: 'https://discord.com/invite/pwutZNx',
              target: '_blank',
              rel: 'noopenner noreferrer'
            },
            'Discord'
          ),
      },
      {
        label: () =>
          h(
            'a',
            {
              href: 'https://twitter.com/codecolorist',
              target: '_blank',
              rel: 'noopenner noreferrer'
            },
            'Twitter'
          ),
      },
      {
        type: 'divider'
      },
      {
        label: () =>
          h(
            'a',
            {
              href: 'https://www.patreon.com/codecolorist',
              target: '_blank',
              rel: 'noopenner noreferrer'
            },
            'Become a Patreon'
          ),
      },
      {
        label: () =>
          h(
            'a',
            {
              href: 'https://www.paypal.com/paypalme/codecolorist',
              target: '_blank',
              rel: 'noopenner noreferrer'
            },
            'Donate on PayPal'
          ),
      }
    ]
  }
]

function handleSelect(key: string) {

}

</script>

<template>
  <n-dropdown placement="right-start" trigger="click" size="small" :options="menuOptions" @select="handleSelect">
    <n-button block :bordered="false">
      <template #icon>
        <n-icon :component="MenuFilled"></n-icon>
      </template>
    </n-button>
  </n-dropdown>
</template>
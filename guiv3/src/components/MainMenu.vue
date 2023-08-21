<script setup lang="ts">
import { Component, h, inject } from 'vue'
import { NIcon } from 'naive-ui'
import {
  AppsOutlined,
  MenuFilled,
  InfoOutlined,
  SecurityFilled,
  LinkFilled,
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
  HomeSharp,
  LinkOffSharp,
} from '@vicons/material'

import {
  Help,
  PlugConnected,
  BrandGithub,
  BrandDiscord,
  BrandTwitter,
  BrandPaypal,
} from '@vicons/tabler'

import type { MenuOption } from 'naive-ui'
import { SESSION_DETACH, WS } from '@/types'

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
    icon: renderIcon(PlugConnected),
    children: [
      {
        label: 'Reload',
        key: 'reload',
        icon: renderIcon(RefreshOutlined),
      },
      {
        label: 'Detach',
        key: 'detach',
        icon: renderIcon(LinkOffSharp),
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
    icon: renderIcon(Help),
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
        icon: renderIcon(BrandGithub),
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
        icon: renderIcon(BrandDiscord),
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
        icon: renderIcon(BrandTwitter),
      },
      {
        type: 'divider'
      },
      {
        label: () =>
          h(
            'a',
            {
              href: 'https://github.com/sponsors/ChiChou',
              target: '_blank',
              rel: 'noopenner noreferrer'
            },
            'Support on GitHub'
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
        icon: renderIcon(BrandPaypal),
      }
    ]
  }
]

const detach = inject(SESSION_DETACH)!
const socket = inject(WS)

function handleSelect(key: string) {
  if (key === 'detach') {
    detach()
  } else if (key === 'kill') {
    socket?.emit('kill')
    detach()
  } else if (key === 'reload') {
    location.reload()
  }
}

</script>

<template>
  <n-dropdown placement="right-start" trigger="click" size="small" :animated="false" :options="menuOptions" @select="handleSelect">
    <n-button block :bordered="false">
      <template #icon>
        <n-icon :component="MenuFilled"></n-icon>
      </template>
    </n-button>
  </n-dropdown>
</template>
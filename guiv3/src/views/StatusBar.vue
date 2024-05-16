<template>
  <footer class="status-bar-global">
    <div class="connection-state" :class="status">
      <n-dropdown
        placement="top-start"
        trigger="click"
        size="small"
        :options="options"
        @select="onSelectSessionMenu"
      >
        <n-button text tag="span" size="tiny">
          <template #icon>
            <n-icon :component="PlugDisconnected24Regular"></n-icon>
          </template>
          {{ status }}
        </n-button>
      </n-dropdown>
    </div>

    <DarkMode />
  </footer>
</template>

<script lang="ts" setup>
import { inject } from 'vue'
import { PlugDisconnected24Regular } from '@vicons/fluent'
import { STATUS, WS, SESSION_DETACH } from '@/types'

import DarkMode from '@/components/DarkMode.vue'

const status = inject(STATUS)
const options = [
  {
    label: 'Reload',
    key: 'reload',
  }, {
    label: 'Kill',
    key: 'kill',
  }, {
    label: 'Detach',
    key: 'detach'
  }
]

const socket = inject(WS)
const detach = inject(SESSION_DETACH)!

function onSelectSessionMenu(key: string) {
  if (key === 'reload') {
    location.reload()
  } else if (key === 'kill') {
    socket?.emit('kill')
    detach()
  } else if (key === 'detach') {
    detach()
  }
}

</script>

<style lang="scss">
:root {
  --n-status-bar-height: 24px;
  --status-background: rgb(0, 122, 204)
}

.status-bar-global {
  height: var(--n-status-bar-height);
  background-color: var(--status-background);
  color: #fff;
  display: flex;

  > div:not(:first-of-type) {
    margin-left: 1rem;
  }
}

.connection-state {
  padding: 0 1rem;
  cursor: pointer;
  span {
    color: #fff;
  }

  &.connected {
    background: #068068;
  }

  &.connecting {
    background: #dfdf13;
    color: #111;
  }

  &.disconnected {
    background: #ea4335;
  }
}
</style>

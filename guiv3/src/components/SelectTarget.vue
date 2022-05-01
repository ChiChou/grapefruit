<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useLoadingBar, useThemeVars } from 'naive-ui'
import axios from '@/plugins/axios'

interface Device {
  name: string;
  removable: boolean;
  id: string;
}

const version = ref('N/A')
const node = ref('N/A')
const devices = ref([] as Device[])

onMounted(() => {
  refresh()
})

const loadingBar = useLoadingBar()
const theme = useThemeVars()

function refresh() {
  loadingBar.start()
  axios.get('/devices')
    .then(({ data }) => {
      devices.value = data.list
      version.value = data.version
      node.value = data.node
      loadingBar.finish()
    })
    .catch(e => {
      loadingBar.error()
    })
}

</script>

<template>
  <main>
    <aside>
      <header>
        <a href="/" class="logo">
          <img src="../assets/logo.svg" alt="Grapefruit" width="160" id="logo" />
        </a>
      </header>

      <p>
        NodeJS {{ node }} <br />
        node-frida {{ version }}
      </p>

      <n-divider />

      <nav>
        <router-link 
          v-for="(dev, i) in devices"
          :to="{ name: 'Apps', params: { device: dev.id } }">
          {{ dev.name }}</router-link>
      </nav>

      <n-divider />

      <nav>
        <a target="_blank" href="https://github.com/chichou/grapefruit">GitHub</a>
        <a target="_blank" href="https://discord.com/invite/pwutZNx">Discord</a>
        <a target="_blank" href="https://www.patreon.com/codecolorist">Support by Patron</a>
        <a target="_blank" href="https://paypal.me/codecolorist">Support by Paypal</a>
      </nav>

      <n-divider />

    </aside>

    <div class="apps">
      <router-view></router-view>
    </div>
  </main>
</template>

<style lang="scss" scoped>
main {
  display: flex;
  flex-direction: row;
}

aside {
  width: 280px;
  padding: 40px;

  nav a {
    color: inherit;
    text-decoration: none;
    display: block;
    padding: 0.5rem 1rem;

    &:hover {
      background: rgba(0, 0, 0, 0.3);
    }
  }
}

.apps {
  flex: 1;
}
</style>

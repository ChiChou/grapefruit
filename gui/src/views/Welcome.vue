<template>
  <div class="welcome">
    <header>
      <h1>
        <img src="../assets/logo.dark.svg" alt="Passionfruit" width="200" id="logo" />
      </h1>
      <h2 class="subtitle">Runtime app instruments for iOS</h2>
      <!-- <b-button @click="connect">Add Remote TCP</b-button> -->
      <aside class="menu">
        <p class="menu-label">Frida version: {{ version }}</p>

        <p class="menu-label">
          Devices
          <!-- <loading v-if="loading" class="is-pulled-right"></loading> -->
        </p>

        <ul class="menu-list">
          <li v-for="dev in devices" :key="dev.id" class="device-list">
            <router-link :to="{ name: 'apps', params: { device: dev.id } }">
              <icon :icon="dev.icon" :width="24" :height="24"></icon>
              {{ dev.name }}
              <button
                v-if="dev.type === 'remote' "
                class="is-pulled-right remove button is-text"
                @click.stop.prevent="remove(dev.id)"
              >
                <b-icon icon="delete" type="is-danger"></b-icon>
              </button>
            </router-link>
          </li>
          <li>
            <a href="#">Add Remote ...</a>
          </li>
          <li v-if="!devices.length">
            <b-icon icon="lan-disconnect" type="is-danger"></b-icon>No device found
          </li>
        </ul>
      </aside>
    </header>

    <router-view class="main"></router-view>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'
import Axios from 'axios'

import Icon from '../components/Icon.vue'

@Component({
  components: {
    Icon
  }
})
export default class Welcome extends Vue {
  version = 'N/A'
  devices = []
  loading = false

  mounted() {
    this.loading = true
    Axios.get('/devices').then(({ data }) => {
      this.loading = false
      this.version = data.version
      this.devices = data.list
    })
  }

  remove() {
    console.log('todo: implement me')
  }
}
</script>

<style lang="scss" scoped>
.welcome {
  display: flex;
  flex-direction: row;

  header {
    width: 320px;
    padding: 40px;
    min-height: 100vh;
    height: 100%;
    background: rgba(0, 0, 0, 0.2);

    position: -webkit-sticky; /* Safari */
    position: sticky;
    top: 0;
  }

  .main {
    flex: 1;
  }
}

h1 {
  margin: 0;
  font-weight: 100;
}

.device-list {
  canvas {
    margin-right: 4px;
  }
}
</style>

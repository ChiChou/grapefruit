<template>
  <div class="device-info">
    <div class="apps" v-if="apps.length">
      <h1 class="sticky">
        {{ info.DeviceName }}
        <a target="_blank" :href="`https://ipsw.me/download/${info.ProductType}/${info.BuildVersion}`" title="Download Firmware">
          iOS {{ info.ProductVersion }} ({{ info.BuildVersion }})
        </a>
      </h1>

      <ul>
        <li :key="app.identifier" v-for="app in apps">
          <a href="#">
            <icon class="icon" :icon="app.largeIcon" :width="32" :height="32"></icon>
            <h2>{{ app.name }}</h2>
            <p>{{ app.identifier }}</p>
          </a>
        </li>
      </ul>
    </div>

    <div v-else class="center has-text-centered">
      <Loading v-if="loading" class="animation" />
      <h1 v-else class="error">Error: Failed to Retrieve Device Information</h1>
    </div>

    <section v-if="device && lockdown" class="info-side">
      <div class="sticky info">
        <a :href="`/api/device/${device}/screen`" target="_blank">
          <img
            v-if="device"
            :src="`/api/device/${device}/screen`"
            width="320"
            class="screenshot"
          />
        </a>

        <p>Serial: {{ info.SerialNumber }}</p>
        <p>BluetoothAddress: {{ info.BluetoothAddress }}</p>
        <p>WiFiAddress: {{ info.WiFiAddress }}</p>
        <p>Firmware: {{ info.FirmwareVersion }}</p>
        <p>Baseband: {{ info.BasebandVersion }}</p>
      </div>
      <!-- <pre>{{ info }}</pre> -->
    </section>
  </div>
</template>

<script lang="ts">
import { Route } from 'vue-router'
import { Component, Vue, Watch } from 'vue-property-decorator'
import Axios from 'axios'

import Icon from '../components/Icon.vue'
import Loading from '../components/Loading.vue'

@Component({
  components: {
    Icon,
    Loading
  }
})
export default class Device extends Vue {
  info = {}
  apps = []
  device = ''
  loading = false
  lockdown = false
  valid = false

  @Watch('$route', { immediate: true })
  private navigate(route: Route) {
    const { device } = route.params

    this.device = device
    this.info = {}
    this.apps = []
    this.loading = true
    this.lockdown = false

    Promise.all([
      Axios.get(`/device/${device}/info`)
        .then(({ data }) => {
          this.info = data
          this.lockdown = true
        })
        .catch(e => {
          this.info = {}
          this.lockdown = false
        }),
      Axios.get(`/device/${device}/apps`)
        .then(({ data }) => {
          this.apps = data
          this.valid = true
        })
        .catch(e => {
          this.apps = []
          this.valid = false
        })
    ]).finally(() => (this.loading = false))
  }
}
</script>

<style lang="scss" scoped>
// pre {
//   white-space: break-spaces;
//   word-break: break-all;
// }

.sticky {
  position: -webkit-sticky; /* Safari */
  position: sticky;
  top: 0;
}

.center {
  margin: auto;
  width: 50%;
  .animation {
    margin: auto;
    width: 144px;
  }

  h1.error {
    font-weight: 100;
    color: #ffffff73;
  }
}

.info p {
  font-size: 0.75rem;
  opacity: 0.75;
  text-align: right;
  margin-right: 20px;
}

.device-info {
  display: flex;
  flex-direction: row;

  h1 {
    background: #1f2424;
    padding: 20px;
    font-size: 2rem;
    font-weight: 100;
    top: 0;
    margin-bottom: 1em;
  }

  .info-side {
    width: 360px;
    padding: 20px;

    > div {
      top: 60px;

      .screenshot {
        border: 10px solid #000;
        border-radius: 20px;
        margin-bottom: 20px;
      }
    }
  }

  .apps {
    flex: 1;
    padding: 30px;

    ul > li {
      display: inline-block;
      margin: 4px;
      width: 280px;

      a {
        display: block;
        padding: 10px;
        overflow-x: hidden;
        border-radius: 4px;

        &:hover {
          background: #111;
        }
      }

      h2 {
        font-size: 1.5rem;
        margin-left: 42px;
        color: #efefef;
      }

      p {
        margin-left: 42px;
        color: #888;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
      }

      canvas {
        float: left;
        margin: 4px;
      }
    }
  }
}
</style>

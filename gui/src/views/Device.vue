<template>
  <div class="device-info">
    <header v-if="apps.length" class="content sticky">
      <h1>
        {{ info.DeviceName }}
        <a
          target="_blank"
          :href="`https://ipsw.me/download/${info.ProductType}/${info.BuildVersion}`"
          title="Download Firmware"
        >iOS {{ info.ProductVersion }} ({{ info.BuildVersion }})</a>
      </h1>

      <b-field grouped group-multiline>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">Serial:</b-tag>
            <b-tag type="is-info">{{ info.SerialNumber }}</b-tag>
          </b-taglist>
        </div>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">Bluetooth:</b-tag>
            <b-tag type="is-info">{{ info.BluetoothAddress }}</b-tag>
          </b-taglist>
        </div>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">WiFi:</b-tag>
            <b-tag type="is-info">{{ info.WiFiAddress }}</b-tag>
          </b-taglist>
        </div>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">Firmware:</b-tag>
            <b-tag type="is-info">{{ info.FirmwareVersion }}</b-tag>
          </b-taglist>
        </div>
        <div class="control">
          <b-taglist attached>
            <b-tag type="is-dark">Baseband:</b-tag>
            <b-tag type="is-info">{{ info.BasebandVersion }}</b-tag>
          </b-taglist>
        </div>
      </b-field>
    </header>

    <section class="flex-frame">
      <div class="apps" v-if="apps.length">
        <ul>
          <li :key="app.identifier" v-for="app in apps">
            <router-link :to="{ name: 'Workspace', params: { device, bundle: app.identifier }}">
              <icon class="icon" :icon="app.largeIcon" :width="32" :height="32"></icon>
              <h2>{{ app.name }}</h2>
              <p>{{ app.identifier }}</p>
            </router-link>
          </li>
        </ul>
      </div>

      <div v-else class="center has-text-centered">
        <Loading v-if="loading" class="animation" />
        <h1 v-else class="error">Error: Failed to Retrieve Device Information</h1>
      </div>

      <section v-if="device && lockdown" class="info-side">
        <div class="screenshot sticky">
          <div class="frame">
            <span @click="screen = !screen" class="toggle" :class="{ active: screen }" title="Toggle Screen">
              <b-icon icon="arrow-left-drop-circle" size="is-medium" type="is-white" />
            </span>
            <a v-if="screen" :href="`/api/device/${device}/screen`" target="_blank">
              <img v-if="device" :src="`/api/device/${device}/screen`" />
            </a>
          </div>
        </div>
        <!-- <pre>{{ info }}</pre> -->
      </section>
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
  screen = true

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
        .catch(() => {
          this.info = {}
          this.lockdown = false
        }),
      Axios.get(`/device/${device}/apps`)
        .then(({ data }) => {
          this.apps = data
          this.valid = true
        })
        .catch(() => {
          this.apps = []
          this.valid = false
        })
    ]).finally(() => (this.loading = false))
  }
}
</script>

<style lang="scss" scoped>
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
  margin-left: 20px;
}

header {
  padding: 20px 40px;
  background: #1f2424;
  box-shadow: 0 2px 1px #0000002e;
  border-bottom: 3px solid #0000000d;
  display: flex;
  flex-direction: row;
  align-items: center;
  justify-content: space-between;

  h1 {
    font-weight: 100;
    top: 0;
    margin-bottom: 0;
  }
}

@media (max-width: 1800px) {
  header {
    display: block;
    h1 {
      margin-bottom: 20px;
    }
  }
}

.flex-frame {
  display: flex;
  flex-direction: row;
  min-height: 100vh;
}

.info-side {
  padding: 20px;

  .screenshot {
    @media (max-width: 1800px) {
      top: 160px;
    }

    @media (min-width: 1801px) {
      top: 100px;
    }

    .frame {
      position: relative;

      .toggle {
        display: block;
        position: absolute;
        left: 0;
        margin-left: -40px;
        opacity: .3;
        cursor: pointer;
        transition: ease-out .2s opacity,transform;

        &.active {
          transform: rotate(180deg);
        }

        &:hover {
          opacity: 1;
        }
      }
    }

    a {
      display: block;
      margin-bottom: 20px;

      img {
        border: 10px solid #000000ad;
        border-radius: 20px;

        @media (max-width: 1800px) {
          width: 240px;
        }

        @media (min-width: 1801px) {
          width: 320px;
        }
      }
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
</style>

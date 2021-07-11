<template>
  <div class="device-info">
    <header class="content">
      <h1 v-if="lockdown">{{ info.name }} {{ info.os.version }}</h1>
      <h1 v-else>{{ shortened }}</h1>
    </header>

    <section>
      <div class="apps" v-if="apps.length">
        <ul>
          <li :key="app.identifier" v-for="app in apps">
            <router-link :to="{ name: 'General', params: { device, bundle: app.identifier }}">
              <img :src="`/api/device/${device}/icon/${app.identifier}`" width="180" height="180">
              <h2>{{ app.name }}</h2>
              <p>{{ app.identifier }}</p>
            </router-link>
          </li>
        </ul>
      </div>

      <div v-else class="center has-text-centered">
        <Loading v-if="loading" class="animation" />
        <h1 v-else-if="error.title" class="error">
          <b-icon icon="message-alert" size="is-medium" />
          <br />
          {{ error.title }}
        </h1>
        <pre v-if="error.stack">{{ error.stack }}</pre>
      </div>
    </section>

    <footer v-if="lockdown">
      <p>
        Arch: {{ info.arch }}
        Version: {{ info.os.version }}
        Platform: {{ info.platform }}
        Access: {{ info.access }}
      </p>
    </footer>
  </div>
</template>

<script lang="ts">
import { Route } from 'vue-router'
import { Component, Vue, Watch } from 'vue-property-decorator'
import Axios from 'axios'

import Loading from '../components/Loading.vue'

interface Failure {
  title?: string;
  stack?: string;
}

@Component({
  components: {
    Loading
  }
})
export default class Device extends Vue {
  info = {}
  apps = []
  device = ''
  loading = false
  lockdown = false
  screen = true
  error: Failure = {}

  get shortened() {
    return this.device.substring(0, 8) + '...'
  }

  @Watch('$route', { immediate: true })
  private navigate(route: Route) {
    const { device } = route.params

    this.device = device
    this.info = {}
    this.apps = []
    this.loading = true
    this.lockdown = false
    this.error = {}

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
          if (!data.length) {
            this.error.title = 'Unable to retrieve apps from this device'
          }
        })
        .catch(e => {
          [this.error.title, this.error.stack] = e.response.data.split('\n', 1)
          this.apps = []
        })
    ]).finally(() => (this.loading = false))
  }
}
</script>

<style lang="scss" scoped>
.center {
  margin: auto;
  min-width: 360px;
  .animation {
    margin: auto;
    width: 144px;
  }

  h1.error {
    font-weight: 100;
    color: #ffffff73;

    .icon {
      margin-right: 4px;
    }
  }
}

.info p {
  font-size: 0.75rem;
  opacity: 0.75;
  margin-left: 20px;
}

header {
  padding: 40px;

  h1 {
    padding-left: 10px;
    padding-right: 10px;
    font-size: 2rem;
    font-weight: 100;
    top: 0;
  }
}

footer {
  padding: 40px 40px 20px 40px;
  color: rgb(124, 124, 124);
}

@media (max-width: 1800px) {
  header {
    display: block;
    h1 {
      margin-bottom: 20px;
    }
  }
}

.main {
  min-height: 100vh;
  display: flex;
  flex-direction: column;
}

.apps {
  padding: 0 20px;

  ul {
    display: grid;
    grid-row-gap: 10px;
    grid-column-gap: 10px;
    justify-content: space-around;
    grid-template-columns: repeat(auto-fill, 15rem);
  }

  ul > li {
    text-align: center;

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
      color: #efefef;
    }

    p {
      color: #888;
      white-space: nowrap;
      overflow: hidden;
      text-overflow: ellipsis;
    }

    img {
      width: 90px;
      height: 90px;
      display: block;
      margin: 1rem auto;
    }
  }
}
</style>

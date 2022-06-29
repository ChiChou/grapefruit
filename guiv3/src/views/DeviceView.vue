<script setup lang="ts">
import axios from '@/plugins/axios'
import { computed } from '@vue/reactivity';

import { useLoadingBar } from 'naive-ui'
import { ref, onMounted, watch, nextTick } from 'vue'
import { useRoute } from 'vue-router'

interface App {
  identifier: string;
  name: string;
}

interface Info {
  name?: string;
  arch?: string;
  os: {
    version?: string;
  };
  platform?: string;
  access?: string;
}

const apps = ref([] as App[])
const info = ref(null as Info | null)
const device = ref('')
const error = ref('')

const shortened = computed(() => {
  const { value } = device
  if (value) return ''

  if (value.length > 6)
    return value.substring(0, 8) + '...'
  else
    return value
})

const route = useRoute()
const loadingBar = useLoadingBar()

async function refresh(dev: string) {
  if (typeof dev !== 'string') throw new Error('invalid route')

  device.value = dev
  error.value = ''

  loadingBar.start()
  axios.get(`device/${dev}/apps`)
    .then(({ data }) => {
      apps.value = data

      document.querySelectorAll('img.lazy').forEach(e => observer.unobserve(e))
      nextTick(() =>
        document.querySelectorAll('img.lazy').forEach(e => observer.observe(e)))
      loadingBar.finish()
    })
    .catch((ex) => {
      apps.value = []
      loadingBar.error()
      console.error('Failed to get apps', ex.response)
      error.value = `Unable to retrieve apps from this device: ${ex.response.data}`
    })
}

const observer = new IntersectionObserver((entries, observer) => {
  entries.forEach(entry => {
    if (!entry.isIntersecting) return

    const img = entry.target as HTMLImageElement
    img.setAttribute('src', img.dataset.src!)
    img.classList.remove('lazy')
    observer.unobserve(img)
  })
})

onMounted(() => {
  refresh(route.params.device as string)
})

watch(() => route.params.device, async newDevice => {
  refresh(newDevice as string)
})

</script>

<template>
  <header class="content">
    <h1 v-if="info">{{ info.name }} {{ info.os.version }}</h1>
    <h1 v-else>{{ shortened }}</h1>
  </header>

  <div class="apps" v-if="apps.length">
    <ul>
      <li :key="app.identifier" v-for="app in apps">
        <router-link :to="{ name: 'General', params: { device, bundle: app.identifier } }">
          <img class="lazy"
            src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
            :data-src="`/api/device/${device}/icon/${app.identifier}`" width="180" height="180">
          <h2>{{ app.name }}</h2>
          <p>{{ app.identifier }}</p>
        </router-link>
      </li>
    </ul>
  </div>

  <n-alert title="Error" type="error" v-if="error">
    {{ error }}
  </n-alert>

  <footer v-if="info">
    <p>
      Arch: {{ info.arch }}
      Version: {{ info.os.version }}
      Platform: {{ info.platform }}
      Access: {{ info.access }}
    </p>
  </footer>
</template>

<style lang="scss" scoped>
ul {
  padding: 20px;
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  grid-gap: 20px;

  li {
    display: block;
    list-style: none;

    a {
      font-weight: 100;
      text-decoration: none;
      text-align: center;
      display: block;

      padding: 20px;
      border-radius: 10px;
      transition: background-color 0.2s ease-in-out;

      &:hover {
        color: var(--highlight-text);
        background-color: var(--highlight-background);
      }
    }

    h2 {
      font-weight: 100;
      margin-bottom: 0;
    }

    p {
      margin: 0;
    }

    img {
      width: 90px;
      height: 90px;
      margin: auto;
      display: block;
    }
  }
}
</style>
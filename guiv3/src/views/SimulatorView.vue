<script setup lang="ts">
import axios from '@/plugins/axios'
import { computed } from '@vue/reactivity';

import { useLoadingBar } from 'naive-ui'
import { ref, onMounted, watch, nextTick } from 'vue'
import { useRoute } from 'vue-router'

type AppType = 'User' | 'System'

interface SimAppInfo {
  ApplicationType: AppType;
  Bundle: string;
  CFBundleDisplayName: string;
  CFBundleExecutable: string;
  CFBundleIdentifier: string;
  CFBundleName: string;
  CFBundleVersion: string;
  DataContainer: string;
  Path: string;
  GroupContainers: { [groupID: string]: string };
}

const apps = ref([] as SimAppInfo[])
const udid = ref('')
const error = ref('')

const shortened = computed(() => {
  const { value } = udid
  if (value) return ''

  if (value.length > 6)
    return value.substring(0, 8) + '...'
  else
    return value
})

const route = useRoute()
const loadingBar = useLoadingBar()

async function refresh(id: string) {
  if (typeof id !== 'string') throw new Error('invalid route')

  udid.value = id
  error.value = ''

  loadingBar.start()
  axios.get(`sim/${id}/apps`)
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
  refresh(route.params.sim as string)
})

watch(() => route.params.sim, async newSimulator => {
  refresh(newSimulator as string)
})

</script>

<template>
  <header class="content">
    <!-- <h1 v-if="info">{{ info.name }} {{ info.os.version }}</h1>
    <h1 v-else>{{ shortened }}</h1> -->
  </header>

  <div class="apps" v-if="apps.length">
    <ul>
      <li :key="app.CFBundleIdentifier" v-for="app in apps">
        <router-link :to="{ name: 'simulator', params: { sim: udid, bundle: app.CFBundleIdentifier } }">
          <img class="lazy"
            src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
            :data-src="`/api/sim/${udid}/icon/${app.CFBundleIdentifier}`" width="180" height="180">
          <h2>{{ app.CFBundleDisplayName }}</h2>
          <p>{{ app.CFBundleIdentifier }}</p>
        </router-link>
      </li>
    </ul>
  </div>

  <n-alert title="Error" type="error" v-if="error">
    {{ error }}
  </n-alert>

  <!-- <footer v-if="info">
    <p>
      Arch: {{ info.arch }}
      Version: {{ info.os.version }}
      Platform: {{ info.platform }}
      Access: {{ info.access }}
    </p>
  </footer> -->
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
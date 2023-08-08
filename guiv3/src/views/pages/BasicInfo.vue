<template>
  <main>
    <n-page-header :subtitle="info.json.CFBundleIdentifier" v-if="info">
      <n-grid :cols="5">
        <n-gi>
          <n-statistic label="Version" :value="info.semVer" />
        </n-gi>
        <n-gi>
          <n-statistic label="MinimumOSVersion" :value="info.minOS" />
        </n-gi>
        <n-gi v-if="info.json.DTSDKBuild">
          <n-statistic label="DTSDKBuild" :value="info.json.DTSDKBuild" />
        </n-gi>
        <n-gi v-if="info.json.DTPlatformVersion">
          <n-statistic label="DTPlatformVersion" :value="info.json.DTPlatformVersion" />
        </n-gi>
      </n-grid>
      <template #title>
        {{ info.name }}
      </template>
      <template #avatar>
        <n-avatar v-if="icon.length" :src="icon" />
      </template>
      <template #footer>
        <dl @click.capture="onSelectText" class="paths">
          <dt>Container</dt>
          <dd>{{ info.home }}</dd>
          <dt>Temporary Directory</dt>
          <dd>{{ info.tmp }}</dd>
          <dt>Installation</dt>
          <dd>{{ info.bundle }}</dd>
          <dt>Executable</dt>
          <dd>{{ info.binary }}</dd>
        </dl>

        <plist-view :root="info.json"></plist-view>
      </template>
    </n-page-header>

    <!-- <pre>{{ JSON.stringify(info, null, 2) }}</pre> -->
  </main>
</template>

<script lang="ts" setup>
import { onMounted, Ref, ref } from 'vue'
import { PlistNode } from '@/types'
import { useTabCommons } from './composables'

import PlistView from '@/components/PlistView.vue'

type InfoDict = {
  CFBundleIdentifier?: string;
  DTSDKBuild?: string;
  MinimumOSVersion?: string;
  DTPlatformVersion?: string;
} & {
  [key: string]: PlistNode
}

interface Info {
  tmp: string;
  home: string;
  version: string;
  semVer: string;
  name: string;
  minOS: string;
  bundle: string;
  binary: string;

  json: InfoDict;
}

const info: Ref<null | Info> = ref(null)
const icon = ref('')

const { setTitle, rpc, tabProps } = useTabCommons();
const props = defineProps(tabProps);

async function load() {
  info.value = await rpc.info.info()

  const data = (await rpc.info.icon()) as ArrayBuffer
  if (!data.byteLength) return
  const blob = new Blob([data], { type: 'image/png' })
  icon.value = URL.createObjectURL(blob)
}

function onSelectText(e: MouseEvent) {
  const target = e.target as HTMLElement
  if (target.tagName.toLowerCase() !== 'dd') return
  const selection = getSelection()
  if (!selection) return
  const range = document.createRange()
  range.selectNodeContents(target)
  selection.removeAllRanges()
  selection.addRange(range)
}

onMounted(() => {
  setTitle(props.tabId!, 'Basic Information')
  load()
})
</script>

<style lang="scss" scoped>
main {
  padding: 1rem;
}

dl.paths {
  dt {
    font-size: .75em;
  }

  dd {
    margin: .5em 0;
    font-family: monospace;
  }
}
</style>
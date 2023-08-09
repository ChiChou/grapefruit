<template>
  <main>
    <n-page-header :subtitle="basics.id" v-if="basics">
      <n-grid :cols="5">
        <n-gi>
          <n-statistic label="Version" :value="basics.version" />
        </n-gi>
        <n-gi v-if="basics.semVer">
          <n-statistic label="Semantic Version" :value="basics.semVer" />
        </n-gi>
        <n-gi>
          <n-statistic label="MinimumOSVersion" :value="basics.minOS" />
        </n-gi>
      </n-grid>
      <template #title>
        {{ basics.label }}
      </template>
      <template #avatar>
        <n-avatar v-if="icon.length" :src="icon" />
      </template>
      <template #footer>
        <dl @click.capture="onSelectText" class="paths">
          <dt>Container</dt>
          <dd>{{ basics.home }}</dd>
          <dt>Temporary Directory</dt>
          <dd>{{ basics.tmp }}</dd>
          <dt>Installation</dt>
          <dd>{{ basics.path }}</dd>
          <dt>Executable</dt>
          <dd>{{ basics.main }}</dd>
        </dl>
      </template>
    </n-page-header>
  </main>
</template>

<script lang="ts" setup>
import { onMounted, Ref, ref } from 'vue'
import { BasicInfo } from '@/../../agent/src/types'
import { useTabCommons, tabProps } from '@/plugins/tab'
import { useRoute } from 'vue-router';


const basics: Ref<BasicInfo | null> = ref(null)

const route = useRoute()
const { udid, bundle } = route.params as { udid: string, bundle: string }
const icon = `/api/${route.name === 'app' ? 'device' : 'sim'}/${udid}/icon/${bundle}`

const props = defineProps(tabProps);
const { entitle, rpc } = useTabCommons(props.tabId!);

async function load() {
  basics.value = await rpc.info.basics()
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
  entitle('Basic')
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
  }
}
</style>@/plugins/tab
<template>
  <n-space justify="center" :wrap-item="true" item-style="margin: 10px 20px">
    <n-input v-model:value="pattern" placeholder="Search" />
    <n-button-group>
      <n-button ghost @click="reload">
        <template #icon>
          <n-icon><refresh-filled /></n-icon>
        </template>
        Reload
      </n-button>
      <n-button ghost @click="expand">
        <template #icon>
          <n-icon><open-in-full-sharp /></n-icon>
        </template>
        Toggle Expand
      </n-button>
    </n-button-group>
  </n-space>
  <PlistView :root="entitlements" :expand-all="expandAll" :pattern="pattern" />
</template>

<script setup lang="ts">
import { tabProps, useTabCommons } from '@/plugins/tab'
import { ref, onMounted, Ref } from 'vue'
import { RefreshFilled, OpenInFullSharp } from '@vicons/material'

import PlistView from '@/components/PlistView.vue'

const props = defineProps(tabProps)
const { entitle, rpc } = useTabCommons(props.tabId!)

const entitlements: Ref<any> = ref(null)
entitle('Entitlements')

const loading = ref(false)
const expandAll = ref(true)
const pattern = ref('')

async function reload() {
  loading.value = true
  entitlements.value = await rpc.checksec.entitlements()
  loading.value = false
}

function expand() {
  expandAll.value = !expandAll.value
}

onMounted(() => {
  reload()
})

</script>

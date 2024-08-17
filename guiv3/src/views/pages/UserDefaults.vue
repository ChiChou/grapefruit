<template>
  <n-data-table :columns="columns" :data="data" :bordered="false" />
</template>

<script setup lang="ts">
import { tabProps, useTabCommons } from '@/plugins/tab'
import { ref, onMounted, Ref } from 'vue'
import { UserDefaultsEntry } from '@/rpc/modules/userdefaults'

const columns = [
  { title: 'Key', key: 'key' },
  { title: 'Value', key: 'readable' },
]

const props = defineProps(tabProps)
const { entitle, rpc } = useTabCommons(props.tabId!)

interface UserDefaultsEntryWithKey extends UserDefaultsEntry {
  key: string
}

const data: Ref<UserDefaultsEntryWithKey[]> = ref([])

onMounted(async () => {
  entitle('NSUserDefaults')

  // todo: make fields editable
  const root = await rpc.userdefaults.enumerate()
  data.value = Object.entries(root).map(([key, item]) => Object.assign({}, item, { key }) as UserDefaultsEntryWithKey)
})

</script>
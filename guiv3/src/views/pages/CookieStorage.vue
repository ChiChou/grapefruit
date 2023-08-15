<template>
  <div v-if="cookies">
    <n-data-table :columns="columns" :data="cookies" :pagination="false" :bordered="false" :loading="loading" />
  </div>
</template>

<script setup lang="ts">
import { NButton, NCheckbox } from 'naive-ui'
import { ref, onMounted, Ref, h } from 'vue'
import { DataTableColumns } from 'naive-ui/lib/data-table'

import { tabProps, useTabCommons } from '@/plugins/tab'
import { Cookie } from '@/../../agent/src/types'

const props = defineProps(tabProps)
const { entitle, rpc } = useTabCommons(props.tabId!)
const loading = ref(false)

const cookies: Ref<Cookie[] | null> = ref(null)

entitle('Cookies')

const createColumns = ({
  modify
}: {
  modify: (row: Cookie) => void
}): DataTableColumns<Cookie> => {
  return [
    {
      title: 'Name',
      key: 'name'
    },
    {
      title: 'Value',
      key: 'value',
    },
    {
      title: 'Domain',
      key: 'domain'
    },
    {
      title: 'Path',
      key: 'path'
    },
    {
      title: 'Secure',
      key: 'isSecure',
      render(row) {
        return h(NCheckbox, {
          checked: row.isSecure,
          disabled: true
        })
      }
    },
    {
      title: 'Actions',
      key: 'actions',
      render(row) {
        return h(
          NButton,
          {
            strong: true,
            tertiary: true,
            size: 'small',
            onClick: () => modify(row)
          },
          { default: () => 'Delete' }
        )
      }
    }
  ]
}

const columns = createColumns({
  modify: (row) => {
    console.log(row)
  }
})

onMounted(async () => {
  loading.value = true
  cookies.value = await rpc.cookies.list() as Cookie[]
  loading.value = false
})

</script>
  
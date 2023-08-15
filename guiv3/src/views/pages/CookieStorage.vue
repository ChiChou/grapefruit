<template>
  <n-space justify="center" :wrap-item="true" item-style="margin: 10px 20px">
    <n-button-group>
      <n-button ghost @click="reload">
        <template #icon>
          <n-icon><refresh-filled /></n-icon>
        </template>
        Reload
      </n-button>
      <n-button ghost @click="clear">
        <template #icon>
          <n-icon><delete-forever-filled /></n-icon>
        </template>
        Clear
      </n-button>
    </n-button-group>
  </n-space>
  <div v-if="cookies">
    <n-data-table :columns="columns" :data="cookies" :pagination="false" :bordered="false" :loading="loading" />
  </div>
</template>

<script setup lang="ts">
import { NButton, NButtonGroup, NCheckbox, useDialog, useMessage } from 'naive-ui'
import { ref, onMounted, Ref, h } from 'vue'
import { DataTableColumns } from 'naive-ui/lib/data-table'
import { RefreshFilled, DeleteForeverFilled, EditSharp, DeleteFilled } from '@vicons/material'

import { tabProps, useTabCommons } from '@/plugins/tab'
import { Cookie } from '@/../../agent/src/types'

const props = defineProps(tabProps)
const { entitle, rpc } = useTabCommons(props.tabId!)
const loading = ref(false)

const cookies: Ref<Cookie[] | null> = ref(null)

entitle('Cookies')

type TableMethods = {
  modify(row: Cookie): void,
  remove(row: Cookie): void,
}

const createColumns = ({ modify, remove }: TableMethods): DataTableColumns<Cookie> => {
  return [
    {
      title: 'Name',
      key: 'name'
    },
    {
      title: 'Value',
      key: 'value',
      render(row) {
        return h('pre', { class: 'cookie-value' }, row.value)
      }
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
          NButtonGroup,
          { ghost: true },
          {
            default: () => [
              h(
                NButton,
                {
                  strong: true,
                  tertiary: true,
                  size: 'small',
                  onClick: () => modify(row)
                },
                { default: () => 'Edit' }
              ),
              h(
                NButton,
                {
                  strong: true,
                  tertiary: true,
                  size: 'small',
                  type: 'error',
                  onClick: () => remove(row)
                },
                { default: () => 'Delete' }
              )
            ]
          }
        )
      }
    }
  ]
}

const dialog = useDialog()
const message = useMessage()

const columns = createColumns({
  modify(row) {
    message.info('Not implemented yet')
  },
  remove(row) {
    message.info('Not implemented yet')
  }
})

onMounted(() => {
  reload()
})

async function clear() {
  dialog.warning({
    title: 'Warning',
    content: 'Are you sure to clear all the cookies of the app?',
    positiveText: 'Confirm',
    negativeText: 'Dismiss',
    async onPositiveClick() {
      loading.value = true

      try {
        await rpc.cookies.clear()
        message.success('Cookies cleared')
      } catch(_) {
        message.error('Failed to clear cookies')
      } finally {
        loading.value = false
        reload()
      }
    },
    onNegativeClick() { }
  })
}

async function reload() {
  loading.value = true
  cookies.value = await rpc.cookies.list() as Cookie[]
  loading.value = false
}

</script>

<style lang="scss">
.cookie-value {
  white-space: pre-wrap;
  word-break: break-all;
  max-width: 640px;
}
</style>
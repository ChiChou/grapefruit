<template>
  <n-data-table size="small" :columns="columns" :data="data" :max-height="height" virtual-scroll />
</template>

<script setup lang="ts">
import { ref, onMounted, Ref, inject, h } from 'vue'
import { RPC, SIDE_PANEL_HEIGHT } from '@/types'
import { DataTableColumns } from 'naive-ui/lib/data-table';

interface Module {
  name: string;
  base: string;
  size: number;
  path: string;
}

const rpc = inject(RPC)!

const columns: DataTableColumns<Module> = [
  {
    title: 'Modules',
    key: 'name',
    fixed: 'left',
    render(row) {
      return h('code', [/*row.base, ' ', */row.name])
    }
  }
]

const height = inject(SIDE_PANEL_HEIGHT)!
const data = ref<Module[]>([])
const loading = ref(false)

onMounted(async () => {
  loading.value = true
  data.value = await rpc.symbol.modules()
  loading.value = false
})

</script>

<style lang="scss">
.modules-container {
  height: 100%;
}
.modules-container code {
  word-wrap: break-word;
  white-space: pre-wrap;
}
</style>
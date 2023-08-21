<template>
  <main>
    <header>
      <n-input v-model:value="pattern" placeholder="Search Modules" />
    </header>
    <ul class="modules">
      <li v-for="m in filtered" :key="m.base">
        <n-tooltip trigger="hover" placement="right">
          <template #trigger>
            <span>{{ m.name }}</span>
          </template>
          <template #default>
            <span>{{ m.base }}</span>
            <br />
            <code>{{ m.path }}</code>
          </template>
        </n-tooltip>
      </li>
    </ul>
  </main>
</template>

<script setup lang="ts">
import { ref, onMounted, inject, h } from 'vue'
import { RPC, SIDE_PANEL_HEIGHT } from '@/types'
import { DataTableColumns } from 'naive-ui/lib/data-table';
import { computed } from 'vue';

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
const pattern = ref('')

async function reload() {
  loading.value = true
  data.value = await rpc.symbol.modules()
  loading.value = false
}

onMounted(() => {
  reload()
})

const filtered = computed(() => {
  return pattern.value?.length ?
    data.value.filter(m => m.name.toLowerCase().includes(pattern.value.toLowerCase())) :
    data.value

})

</script>

<style lang="scss" scoped>
main {
  display: flex;
  flex-direction: column;
  height: 100%;
}

header {
  padding: 10px;
}

ul.modules {
  flex: 1;
  margin: 0;
  padding: 0;
  overflow-x: hidden;
  overflow-y: auto;

  li {
    display: block;
    list-style: none;

    span {
      display: inline-block;
      padding: 4px 20px;
    }

    &:hover {
      background: rgba(0, 0, 0, .3);
    }
  }
}
</style>
<template>
  <div>{{ state }}</div>
</template>

<script lang="ts" setup>
import { inject, onMounted, ref } from 'vue'
import { RPC } from '@/types'

const rpc = inject(RPC)!
const info = ref({})

const props = defineProps({
  state: Object
})

onMounted(async () => {
  info.value = await rpc.info.info()
})
</script>
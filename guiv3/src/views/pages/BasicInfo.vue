<template>
  <div>{{ info }}</div>
</template>

<script lang="ts" setup>
import { inject, onMounted, ref } from 'vue'
import { RPC, SET_TAB_TITLE } from '@/types'
import { pageProps } from './composables'

const rpc = inject(RPC)!
const info = ref({})

const props = defineProps(pageProps)
const setTitle = inject(SET_TAB_TITLE)!

onMounted(async () => {
  setTitle(props.tabId!, 'Basic Information')
  info.value = await rpc.info.info()
})
</script>
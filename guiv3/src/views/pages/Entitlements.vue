<template>
  <PlistView :root="entitlements" />
</template>

<script setup lang="ts">
import { tabProps, useTabCommons } from '@/plugins/tab'
import { ref, onMounted, Ref } from 'vue'

import PlistView from '@/components/PlistView.vue'

const props = defineProps(tabProps)
const { entitle, rpc } = useTabCommons(props.tabId!)

const entitlements: Ref<any> = ref(null)

onMounted(async () => {
  entitle('Entitlements')
  entitlements.value = await rpc.checksec.entitlements()
})

</script>

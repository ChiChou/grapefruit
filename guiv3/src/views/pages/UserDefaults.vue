<template>
    <PlistView :root="plist" />
  </template>
  
  <script setup lang="ts">
  import { tabProps, useTabCommons } from '@/plugins/tab'
  import { ref, onMounted, Ref } from 'vue'
  
  import PlistView from '@/components/PlistView.vue'
  
  const props = defineProps(tabProps)
  const { entitle, rpc } = useTabCommons(props.tabId!)
  
  const plist: Ref<any> = ref(null)
  
  onMounted(async () => {
    entitle('NSUserDefaults')
    // todo: make fields editable
    plist.value = await rpc.info.userDefaults()
  })
  
  </script>
  
<template>
    <PlistView :root="plist" />
  </template>
  
  <script setup lang="ts">
  import { tabProps, useTabCommons } from '@/plugins/tab'
  import { ref, onMounted, Ref } from 'vue'
  import { UserDefaultsDict } from '@/rpc/modules/userdefaults'

  import PlistView from '@/components/PlistView.vue'
  
  const props = defineProps(tabProps)
  const { entitle, rpc } = useTabCommons(props.tabId!)
  
  const plist: Ref<UserDefaultsDict> = ref({})
  
  onMounted(async () => {
    entitle('NSUserDefaults')
    // todo: make fields editable
    plist.value = await rpc.userdefaults.enumerate()
  })
  
  </script>
  
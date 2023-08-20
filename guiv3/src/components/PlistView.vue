<template>
  <n-tree block-line :data="tree" class="plist" selectable 
    expand-on-click :default-expand-all="expandAll"
    :pattern="pattern" />
</template>

<script lang="ts" setup>
import { computed, h } from 'vue'
import { TreeOption } from 'naive-ui'
import { PlistNode, PlistValue } from '@/types';

function treeify(root: PlistNode): TreeOption[] {
  let idx = 0;

  function visit(key: string, node: PlistValue): TreeOption {
    if (Array.isArray(node)) {
      return {
        key: idx++,
        label: key,
        children: node.map((e, i) => visit(`[${i}]`, e))
      }
    }

    if (typeof node === 'object') {
      return {
        key: idx++,
        prefix: () => h('span', key),
        children: Object.entries(node).map(([key, e]) => visit(key, e))
      }
    }

    return {
      key: idx++,
      prefix: () => h('span', { class: 'dictkey' }, key),
      label: `${node}`,
    }
  }

  return Object.entries(root).map(([key, val]) => visit(key, val))
}

const props = defineProps({
  root: Object,
  expandAll: Boolean,
  pattern: String,
})

const tree = computed(() => props.root ? treeify(props.root) : [])
</script>

<style lang="scss">
.dictkey {
  color: #c41d7f;

  &::after {
    content: ': ';
    color: var(--n-node-text-color);
  }
}
</style>
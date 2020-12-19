<template>
  <aside class="side-panel">
    <header>
      <b-progress class="thin" :class="{ show: loading }"></b-progress>
      <input v-model="keyword" ref="keyword" placeholder="Search Class Name..." class="search" tabindex="-1">
      <b-tabs v-model="index" expanded class="header-only">
        <b-tab-item label="Main" icon="folder-home-outline" :disabled="loading" />
        <b-tab-item label="App" icon="folder-cog-outline" :disabled="loading" />
        <b-tab-item label="Global" icon="folder-cog-outline" :disabled="loading" />
      </b-tabs>
    </header>
    <main class="scroll">
      <ul class="classes" :class="{ loading }">
        <RecycleScroller
          class="scroller"
          page-mode
          :items="list"
          :item-size="32"
          key-field="id"
          v-slot="{ item }"
        >
          <li class="node" @click="$bus.$emit('openTab', 'ClassInfo', 'Class: ' + item.name, { name: item.name })">
            <b-icon icon="file-cog-outline"></b-icon>&nbsp;{{ item.name }}
          </li>
        </RecycleScroller>
      </ul>
    </main>
  </aside>
</template>

<script lang="ts">
import debounce from 'lodash.debounce'

import { Component, Vue, Watch } from 'vue-property-decorator'

const ScopeValues = ['__main__', '__app__', '__global__'] as const

type Scope = typeof ScopeValues[number]
type Item = {
  id: number;
  name: string;
}

@Component({
  watch: {
    keyword: debounce(function(this: Runtime, newVal: string) {
      this.refresh(this.scope, newVal)
    }, 500)
  }
})
export default class Runtime extends Vue {
  keyword = ''

  loading = false

  list: Item[] = []
  index = 1 // default: __app__

  get scope(): Scope {
    return ScopeValues[this.index]
  }

  mounted() {
    this.refresh(this.scope)
  }

  @Watch('scope')
  scopeChanged(val: Scope) {
    this.refresh(val, this.keyword)
  }

  refresh(scope: Scope, keyword?: string) {
    this.loading = true
    this.$rpc.classdump
      .search(scope, keyword)
      .then((list: string[]) => {
        this.list = list.map((name, id) => ({ id, name }))
      })
      .finally(() => {
        (this.$refs.keyword as HTMLInputElement).focus()
        this.loading = false
      })
  }
}
</script>

<style lang="scss">
ul.classes {
  padding: 10px;
  color: #aaa;

  &.loading {
    display: none;
  }

  & li {
    cursor: pointer;
    text-overflow: ellipsis;
    overflow: hidden;
    white-space: nowrap;
    transition: .2s ease-in color;

    &:hover {
      color: #fff;
    }
  }
}

.class-dump-scope-select {
  display: flex;

  > div {
    > input[type=radio] {
      margin-right: 4px;
    }

    padding: 10px;
    align-items: center;
    justify-content: center;
    display: flex;
    flex-grow: 1;
  }

}
</style>

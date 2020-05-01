<template>
  <div class="runtime-panel">
    <header>
      <input v-model="keyword" placeholder="Search..." class="search">
      <section class="class-dump-scope-select">
        <div>
          <input type="radio" id="one" value="__main__" v-model="scope" :disabled="loading">
          <label for="one">Main</label>
        </div>

        <div>
          <input type="radio" id="one" value="__app__" v-model="scope" :disabled="loading">
          <label for="one">App</label>
        </div>

        <div>
          <input type="radio" id="one" value="__global__" v-model="scope" :disabled="loading">
          <label for="one">Global (slow)</label>
        </div>
      </section>
    </header>
    <main class="scroll">
      <class :node="tree" :filter="filter" />
    </main>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Watch } from 'vue-property-decorator'
import { CreateElement, VNode } from 'vue'
import bus from '../../bus'

type scope = '__app__' | '__main__' | '__global__'

function * visit(h: CreateElement, node: object, filter: RegExp, depth = 0): IterableIterator<string | VNode> {
  for (const [name, child] of Object.entries(node)) {
    const children = [...visit(h, child, filter, depth + 1)]
    let match = typeof filter === 'undefined'
    if (!match && filter) {
      match = Boolean(name.match(filter))
    }

    if (match) {
      const label = h('span',
        {
          style: {
            marginLeft: depth + 'em'
          },
          on: {
            click: () => bus.bus.$emit('openTab', 'ClassInfo', 'Class: ' + name, { name })
          }
        }, name)
      children.unshift(label)
    }
    yield h('li', { attrs: { class: 'node' } }, children)
  }
}

Vue.component('class', resolve => {
  Vue.nextTick(() => {
    resolve({
      render(h: CreateElement) {
        return h('ul', { attrs: { class: 'hierarchy-tree-root' } }, [...visit(h, this.node, this.filter)])
      },
      props: {
        node: {
          type: Object,
          required: true
        },
        filter: RegExp
      }
    })
  })
})

@Component
export default class Runtime extends Vue {
  keyword = ''

  scope: scope = '__app__'
  tree: object = {}
  loading = false

  get filter(): RegExp | undefined {
    if (this.keyword) return new RegExp(this.keyword, 'i')
  }

  mounted() {
    this.refresh(this.scope)
  }

  @Watch('scope')
  scopeChanged(val) {
    this.refresh(val)
  }

  refresh(scope) {
    this.loading = true
    this.$rpc.classdump.hierarchy(scope).then((tree: object) => {
      this.tree = tree
    }).finally(() => {
      this.loading = false
    })
  }
}
</script>

<style lang="scss">
.hierarchy-tree-root {
  padding: 10px;
  color: #aaa;

  .node {
    display: block;

    > span {
      &::before {
        font: normal normal normal 18px/1 "Material Design Icons";
        content: "\F0770";
        margin-right: 4px;
        color: #616161;
      }

      font-weight: 100;
      cursor: pointer;
      color: #ddd;
      transition: 0.2s color;
      &:hover {
        color: #ffeb3b;
      }
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
  // .control {
  //   flex-grow: 1;
  // }
}

.runtime-panel {
  display: flex;
  flex-direction: column;
  height: 100%;

  .search {
    width: 100%;
    padding: 8px;
    background: #222;
    color: #959595;
    font-size: 1rem;
    border: 1px solid transparent;

    &:focus {
      border-color: #2196f3;
      color: #eee;
    }
  }

  .scroll {
    background: #242424;
    box-shadow: 0 4px 4px #00000030 inset;
    overflow: auto;
    flex: 1;
  }
}

</style>

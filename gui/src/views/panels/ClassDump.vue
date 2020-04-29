<template>
  <div>
    <section>
      <b-field class="class-dump-scope-select">
        <b-radio-button
          v-model="scope"
          native-value="__main__"
          :disabled="loading"
        >
          <b-icon icon="circle-slice-1"></b-icon>
          <span>Executable</span>
        </b-radio-button>

        <b-radio-button
          v-model="scope"
          :disabled="loading"
          native-value="__app__"
        >
          <b-icon icon="circle-slice-7"></b-icon>
          <span>App</span>
        </b-radio-button>

        <b-radio-button v-model="scope"
            native-value="__global__"
            :disabled="loading">
          <b-icon icon="circle-slice-8"></b-icon>
          All (slow)
        </b-radio-button>
      </b-field>
    </section>

    <class :node="tree" :filter="filter" />
  </div>
</template>

<script lang="ts">
import { Component, Vue, Watch, Prop } from 'vue-property-decorator'
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
    yield h('li', { attrs: { class: 'hierarchy-tree-node' } }, children)
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
export default class ClassDump extends Vue {
  scope: scope = '__app__'
  tree: object = {}
  loading = false

  @Prop()
  keyword?: string

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
}

.hierarchy-tree-node {
  // background: #ff980021;
  // color: #FFC107;
  // text-shadow: 1px 1px 1px #00000075;
  display: block;

  > span {
    cursor: pointer;
    &:hover {
      color: #ffeb3b;
    }
  }
}

.class-dump-scope-select {
  display: flex;
  .control {
    flex-grow: 1;
  }
}
</style>

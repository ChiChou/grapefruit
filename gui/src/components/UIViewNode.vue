<template>
  <li
      class="uiview"
      :class="{ selected }"
      @mouseenter.prevent.stop="highlight"
      @mouseleave.prevent.stop="dismiss"
      @click.prevent.stop="select"
    >
    <p :style="{ paddingLeft: depth + 1 + 'em' }">
      <span
        @click.prevent.stop="expanded = !expanded"
        v-if="node.children && node.children.length"
        class="mdi"
        :class="{ 'mdi-minus': expanded, 'mdi-plus': !expanded }"
      ></span>
      <span v-else class="mdi mdi-dots-horizontal"></span>
      <Description v-if="node.description" class="description" :text="node.description" />
      <span
        v-if="node.delegate && node.delegate.name"
        @click="classinfo(node.delegate.name)"
        class="delegate"
      >delegate: {{ node.delegate.description }}</span>
    </p>
    <ul class="uiview-subviews" v-if="expanded">
      <li v-for="(child, index) in node.children" :key="index">
        <UIViewNode :node="child" :depth="depth + 1" />
      </li>
    </ul>
  </li>
</template>

<script lang="ts">
import { Component, Vue, Prop } from 'vue-property-decorator'
import { CreateElement } from 'vue'
import { tokenize } from '@/utils'
import $bus from '@/bus'

type Frame = [number, number, number, number]

interface Delegate {
  name?: string;
  description?: string;
}

interface Node {
  clazz: string;
  description: string;
  children: Node[];
  frame: Frame;
  preview: ArrayBuffer;
  delegate?: Delegate;
}

const empty: Node = {
  clazz: '',
  description: '',
  children: [],
  frame: [0, 0, 0, 0],
  preview: new ArrayBuffer(0)
}

interface Token {
  type: string;
  word: string;
}

function * scan(text: string): IterableIterator<Token> {
  const delimiters = '\'<>: ;=()'
  let prev
  let type: string
  const operators = '<,>;:='
  const booleanValues = ['YES', 'NO']
  const tokens = tokenize(text, delimiters)
  for (const token of tokens) {
    if (token === '\'') {
      let next
      let word = token
      while ((next = tokens.next())) {
        if (next.done) break
        const { value } = next
        word += value
        if (value === '\'') break
      }
      yield {
        type: 'str',
        word
      }
      continue
    } if (token.match(/^0x?[\da-fA-F]+$/)) {
      type = 'hex'
    } else if (token.match(/^[\d.]+$/)) {
      type = 'num'
    } else if (operators.includes(token)) {
      type = 'op'
    } else if (prev === '<') {
      type = 'clazz'
    } else if (booleanValues.includes(token)) {
      type = 'bool'
    } else {
      type = ''
    }
    yield {
      type,
      word: token
    }
    prev = token
  }
}

@Component
class Description extends Vue {
  @Prop({ required: true })
  text!: string

  render(createElement: CreateElement) {
    return createElement(
      'span',
      {},
      [...scan(this.text)].map(token => {
        if (!token.type) return token.word

        if (token.type === 'clazz') {
          const name = token.word
          return createElement('a', {
            on: {
              click: () => {
                $bus.bus.$emit('openTab', 'ClassInfo', 'Class: ' + name, { name })
              }
            },
            attrs: {
              class: 'clazz'
            }
          }, [name])
        }

        return createElement('span', {
          attrs: {
            class: token.type
          }
        }, [token.word])
      })
    )
  }
}

@Component({
  name: 'UIViewNode',
  components: {
    Description
  }
})
export default class UIViewNode extends Vue {
  @Prop({ default: () => empty })
  node!: Node

  @Prop({ default: 0 })
  depth!: number

  expanded = true
  selected = false

  dismiss() {
    this.$rpc.ui.dismissHighlight()
  }

  select() {
    this.selected = true
    let node = this as UIViewNode
    while (node.depth > 0) {
      node = node.$parent as UIViewNode
    }

    if (node) node.$parent.$emit('selectNode', this)
  }

  highlight() {
    this.$rpc.ui.highlight(this.node.frame)
  }

  classinfo(name: string) {
    this.$bus.$emit('openTab', 'ClassInfo', 'Class: ' + name, { name })
  }
}
</script>

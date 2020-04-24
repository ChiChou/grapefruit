<template>
  <li class="uiview" @mouseenter.prevent.stop="highlight"  @mouseleave.prevent.stop="dismiss">
    <p :style="{ paddingLeft: depth + 1 + 'em' }">
      <span
        @click.prevent.stop="expanded = !expanded"
        v-if="node.children && node.children.length"
        class="mdi"
        :class="{ 'mdi-minus': expanded, 'mdi-plus': !expanded }"
      ></span>
      <span v-else class="mdi mdi-dots-horizontal"></span>
      <!-- <span class="description">{{ node.description }}</span> -->
      <syntax v-if="node.description" class="description" :text="node.description" />
      <span v-if="node.delegate"> delegate: {{ node.delegate }}</span>
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

type Frame = [number, number, number, number]

interface Node {
  description?: string;
  children?: Node[];
  frame?: number[];
  delegate?: string;
}

const empty: Node = {}

interface Token {
  type: string;
  word: string;
}

function * scan(text: string) {
  let word
  let m
  let sub = text

  const regs = {
    hex: /^0x?[\da-fA-F]+/,
    num: /^\d+/,
    '': /^\s+/,
    op: /^[<,>()=;]+/,
    clazz: /^[A-Z][\w.]+:/
  }

  while (sub && sub.length) {
    let found = false
    for (const [type, reg] of Object.entries(regs)) {
      m = sub.match(reg)
      if (m) {
        if (word) {
          yield {
            type: '',
            word
          }
        }
        word = m[0]
        yield {
          type,
          word
        }
        sub = sub.substr(word.length)
        word = ''
        found = true
        break
      }
    }

    if (!found) {
      word += sub.charAt(0)
      sub = sub.substr(1)
    }
  }
}

Vue.component('syntax', resolve => {
  Vue.nextTick(() => {
    resolve({
      render(createElement: CreateElement) {
        return createElement(
          'span',
          {},
          [...scan(this.text)].map(token => {
            return createElement(
              'span',
              {
                attrs: {
                  class: token.type
                }
              },
              [token.word]
            )
          })
        )
      },
      props: {
        text: {
          type: String,
          required: true
        }
      }
    })
  })
})

@Component({
  name: 'UIViewNode'
})
export default class UISnapShot extends Vue {
  @Prop({ default: () => empty })
  node!: Node

  @Prop({ default: 0 })
  depth!: number

  expanded = true
  selected = false

  dismiss() {
    this.$rpc.ui.dismissHighlight()
  }

  highlight() {
    // console.log(this.node.frame)
    this.$rpc.ui.highlight(this.node.frame)
  }
}
</script>

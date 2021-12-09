<template>
  <div class="jsvalue">
    <ul id="v-for-object" class="demo">
      <li class="entry" v-for="(value, name) in obj" :key="name">
        <span class="key">{{ name }}</span><JSObject :value="value"></JSObject>
      </li>
    </ul>
  </div>
</template>

<script lang="ts">
import { CreateElement } from 'vue'
import { Component, Vue, Prop } from 'vue-property-decorator'

import $bus from '@/bus'

interface NSObject {
  type?: 'instance' | 'block' | 'class' | 'dict' | 'array' | 'function';
  clazz?: string;
  handle?: string;
  invoke?: string;
  size?: number;
  source?: string;
}

@Component
class JSObject extends Vue {
  @Prop({ required: true })
  value!: object

  linkToClass(createElement: CreateElement, name?: string) {
    return createElement('a', {
      on: {
        click() {
          if (name) $bus.bus.$emit('openTab', 'ClassInfo', 'Class: ' + name, { name })
        }
      }
    }, name)
  }

  linkToInvoke(createElement: CreateElement, addr?: string) {
    return createElement('a', {
      on: {
        click() {
          if (addr) $bus.bus.$emit('openTab', 'Disasm', 'Disassembly @' + addr, { addr })
        }
      }
    }, addr)
  }

  renderHandle(createElement: CreateElement, handle?: string) {
    return createElement('span', { attrs: { class: 'handle' } }, handle)
  }

  render(createElement: CreateElement) {
    if (typeof this.value === 'object') {
      const obj = this.value as NSObject
      const { type } = obj
      if (type === 'instance') {
        const clazz = this.linkToClass(createElement, obj.clazz)
        const handle = this.renderHandle(createElement, obj.handle)
        return createElement(
          'span',
          {},
          ['<', clazz, ' ', handle, '>']
        )
      } else if (type === 'block') {
        const handle = this.renderHandle(createElement, obj.handle)
        return createElement(
          'span',
          {},
          ['<Block ', handle, ' invoke=', this.linkToInvoke(createElement, obj.invoke), '>']
        )
      } else if (type === 'class') {
        const clazz = this.linkToClass(createElement, obj.clazz)
        return createElement(
          'span',
          {},
          ['<Class ', clazz, '>']
        )
      } else if (type === 'dict') {
        return createElement('code', {}, `Dictionary{${obj.size} entries}`)
      } else if (type === 'array') {
        return createElement('span', {}, `Array[${obj.size}]`)
      } else if (type === 'function') {
        return createElement('code', {}, obj.source)
      }
      return createElement(
        'span',
        {},
        `${obj}`
      )
    }

    return createElement(
      'span',
      { class: typeof this.value },
      [`${this.value}`]
    )
  }
}

@Component({
  components: {
    JSObject
  }
})
export default class JSValue extends Vue {
  @Prop()
  obj!: object
}
</script>

<style lang="scss">
.jsvalue {
  .entry {
    font-family: "Fira Code", monospace;
    margin: .25rem .25rem .25rem 1em;
    color: #999;

    .handle {
      color: #e33e3a;
    }
  }

  span.key {
    color: #e36eec;
    margin-right: .5em;
    &::after {
      content: ':';
    }
  }
}
</style>

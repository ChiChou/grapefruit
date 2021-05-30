<template>
  <div>
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

import $bus from '../bus'

interface NSObject {
  type?: 'instance' | 'block' | 'class' | 'dict' | 'array';
  clazz?: string;
  handle?: string;
  invoke?: string;
  size?: number;
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

  render(createElement: CreateElement) {
    if (typeof this.value === 'object') {
      const obj = this.value as NSObject
      const { type } = obj
      // console.log(type, JSON.stringify(this.value))
      if (type === 'instance') {
        const clazz = this.linkToClass(createElement, obj.clazz)
        const handle = createElement('span', {}, obj.handle)
        return createElement(
          'span',
          {},
          ['<', clazz, ' ', handle, '>']
        )
      } else if (type === 'block') {
        return createElement(
          'span',
          {},
          ['<Block ', obj.handle, ' invoke=', this.linkToInvoke(createElement, obj.invoke), '>']
        )
      } else if (type === 'class') {
        const clazz = this.linkToClass(createElement, obj.clazz)
        return createElement(
          'span',
          {},
          ['<', clazz, ' >']
        )
      } else if (type === 'dict') {
        return createElement('code', {}, `Dictionary of ${obj.size} elements`)
      } else if (type === 'array') {
        return createElement('code', {}, `Dictionary of ${obj.size} elements`)
      }
      return createElement(
        'span',
        {},
        'todo'
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

<style lang="scss" scoped>
.entry {
  font-family: "Fira Code", monospace;
  margin: .5rem;
}

span.key {
  margin-right: .5em;
  &::after {
    content: ':';
  }
}
</style>

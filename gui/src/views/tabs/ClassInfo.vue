<template>
  <div class="pad">
    <nav class="breadcrumb" aria-label="breadcrumbs">
      <ul v-if="clazz.prototypeChain">
        <li v-for="(cls, index) in clazz.prototypeChain" :key="index">
          <a @click="$bus.$emit('openTab', 'ClassInfo', 'Class: ' + cls, { name: cls })">{{ cls }}</a>
        </li>
      </ul>
    </nav>

    <section class="content">
      <h1>{{ name }}</h1>
      <p>Module: <code>{{ clazz.module }}</code></p>

    </section>
    <b-tabs :animated="false">
      <b-tab-item label="Methods" class="content" icon="rocket-outline">
          <b-field grouped class="search-box" position="is-right">
            <b-input
              placeholder="Search..."
              v-model="keyword"
              type="search"
              icon="magnify">
            </b-input>

            <b-checkbox v-model="includeSuper">
              <span>Include Inherited</span>
              <b-icon icon="file-tree"></b-icon>
            </b-checkbox>
          </b-field>
        <ul>
          <li class="monospace method" v-for="(sel, index) in selectors" :key="index">
            <a @click="$bus.$emit('openTab', 'Disasm', 'Disassembly @' + sel.impl, { addr: sel.impl })">@{{ sel.impl }}</a>
            {{ sel.name }}
          </li>
        </ul>
      </b-tab-item>

      <b-tab-item label="Protocols" class="content" icon="power-plug">
        <ul v-if="clazz.protocols" class="protocols">
          <li v-for="(proto, protocolName) in clazz.protocols" :key="protocolName">
            <h3>{{ protocolName }} <span v-if="proto.handle">@{{proto.handle}}</span></h3>
            <ul v-if="proto.properties && proto.properties">
              <li v-for="(prop, propertyName) in proto.properties" :key="propertyName">{{ propertyName }}</li>
            </ul>

            <ul v-if="proto.methods">
              <li v-for="(method, methodName) in proto.methods" :key="methodName" class="monospace">
                {{ methodName }}
                <code>{{ method.types}}</code>
                <b-tag v-if="method.required">required</b-tag>
              </li>
            </ul>
          </li>
        </ul><p v-else>This class implements no protocol</p>
      </b-tab-item>

      <b-tab-item label="ivars" class="content" icon="format-list-bulleted">
        <ul>
          <li v-for="(name, offset) in clazz.ivars" :key="offset"><code>{{ offset }}</code> {{ name }}</li>
          <li v-if="!clazz.ivars || !Object.keys(clazz.ivars).length">This class doesn't have any ivar</li>
        </ul>
      </b-tab-item>
    </b-tabs>
  </div>
</template>

<script lang="ts">
import debounce from 'lodash.debounce'

import { Prop, Component, Watch } from 'vue-property-decorator'
import Base from './Base.vue'

type Method = {
  name: string;
  impl: string;
}

interface Info {
  protocols?: object[];
  methods: { [key: string]: Method };
  prototypeChain?: string[];
  own?: string[];
  ivars?: { [offset: string]: string };
  module?: string;
}

@Component
export default class ClassInfo extends Base {
  updateFilter?: Function

  clazz: Info = {
    methods: {}
  }

  includeSuper = false
  keyword = ''

  selectors: Iterable<Method> = []

  @Prop({ required: true })
  name!: string

  @Watch('keyword')
  input(keyword: string) {
    if (!this.clazz) return
    if (!this.updateFilter) return
    this.updateFilter(keyword, this.includeSuper)
  }

  @Watch('includeSuper')
  toggleInheritance(val: boolean) {
    if (!this.updateFilter) return
    this.updateFilter(this.keyword, val)
  }

  applySearch(keyword: string, includeSuper: boolean) {
    const { clazz } = this
    function * filter(): IterableIterator<Method> {
      if (!clazz) return []
      const re = new RegExp(keyword, 'i')
      const queue = includeSuper ? Object.keys(clazz.methods) : clazz.own
      if (!queue) return []
      for (const key of queue) {
        if (key.match(re)) yield clazz.methods[key]
      }
    }

    this.selectors = filter()
  }

  mounted() {
    this.updateFilter = debounce(this.applySearch)

    this.loading = true
    this.$rpc.classdump.inspect(this.name)
      .then((response: Info) => {
        this.clazz = response
        this.applySearch('', this.includeSuper)
      })
      .finally(() => {
        this.loading = false
      })
  }
}
</script>

<style lang="scss" scoped>
h1, h2 {
  font-weight: 100;
}

.search-box {
  position: sticky;
  top: 20px;
  display: flex;
}

.monospace {
  font-family: "Fira Code", monospace;
}

.method:hover {
  background: rgba(0, 0, 0, .1);
}

.protocols > li {
  margin-bottom: 40px;
}
</style>

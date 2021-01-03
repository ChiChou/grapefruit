<template>
  <aside class="side-panel">
    <header>
      <b-progress class="thin" :class="{ show: loading }"></b-progress>
      <b-field :type="queryState" :message="error">
        <b-input v-model="query" placeholder="Search Api" tabindex="-1" class="square"></b-input>
      </b-field>

      <b-tabs v-model="index" expanded class="header-only">
        <b-tab-item
          label="Module"
          icon="folder-cog-outline"
          :disabled="loading"
        />
        <b-tab-item
          label="Objective-C"
          icon="folder-home-outline"
          :disabled="loading"
        />
      </b-tabs>
    </header>
    <main class="scroll">
      <ul class="functions" :class="{ loading }">
        <RecycleScroller
          class="scroller"
          page-mode
          :items="list"
          :item-size="64"
          key-field="id"
          v-slot="{ item }"
        >
          <li class="api-module-node">
            <template v-if="kind === 'module'">
              <p class="overflow"><b-icon icon="meteor" size="is-small"></b-icon><span>{{ item.symbol }}</span></p>
              <p class="overflow api-module-path">
                <a @click="$bus.$emit('openTab', 'Disasm', 'Disassembly @' + item.address, { addr: item.address })">
                  @{{ item.address }}</a>
                {{ item.module }}
              </p>
            </template>
            <template v-else>
              <p class="overflow"><b-icon icon="meteor" size="is-small"></b-icon><span>{{ item.name }}</span></p>
              <p class="api-module-path overflow">
                <a @click="$bus.$emit('openTab', 'Disasm', 'Disassembly @' + item.address, { addr: item.address })">
                  @{{ item.address }}</a>
              </p>
            </template>
          </li>
        </RecycleScroller>
      </ul>
    </main>
  </aside>
</template>

<script lang="ts">
import debounce from 'lodash.debounce'
import { Component, Vue, Watch } from 'vue-property-decorator'

const PossibleTypes = ['module', 'objc'] as const

type Kind = typeof PossibleTypes[number]

@Component({
  watch: {
    query: debounce(function(this: ApiResolver, newVal: string) {
      this.refresh(this.kind, newVal)
    }, 500)
  }
})
export default class ApiResolver extends Vue {
  loading = false
  query = ''
  index = 0 // default: module
  error = ''
  list: object[] = []

  mounted() {
    this.refresh(this.kind)
  }

  get queryState() {
    return this.error ? 'is-danger' : ''
  }

  get kind(): Kind {
    return PossibleTypes[this.index]
  }

  refresh(kind: Kind, query?: string) {
    if (!this.query) {
      this.list = []
      return
    }

    this.loading = true
    this.$rpc.symbol
      .resolve(this.kind, query)
      .then((list: string[]) => {
        this.error = ''
        if (kind === 'module') {
          this.list = list.map((item, id) => Object.assign({ id }, item))
        } else {
          this.list = list.map((item, id) => Object.assign({ id }, item))
        }
      })
      .catch((e: Error) => {
        this.error = e.message
        this.list = []
      })
      .finally(() => {
        this.loading = false
      })
  }

  @Watch('kind')
  kindChanged(val: Kind) {
    this.refresh(val, this.query)
  }
}
</script>

<style lang="scss">
.api-module-node {
  padding: 10px;
  color: #fefefe;

  .icon {
    margin-right: .5em;
  }

  &:hover {
    background: rgba(0, 0, 0, 0.2);
  }

  .overflow {
    text-overflow: ellipsis;
    overflow: hidden;
    white-space: nowrap;
  }

  .api-module-path {
    font-size: 0.75em;
    color: #afadaf;
  }
}
</style>

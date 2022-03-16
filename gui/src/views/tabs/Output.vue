<template>
  <div class="container">
    <header class="toolbar">
      <b-checkbox v-model="autoScroll">Auto Scroll</b-checkbox>
    </header>
    <main class="output" ref="logs">
      <RecycleScroller
        class="scroller"
        page-mode
        :items="logs"
        :item-size="32"
        key-field="id"
        ref="scroller"
        v-slot="{ item }"
      >
        <li class="log-item" :class="{ on: item.selected }" @click="select(item.id)">
          <b-icon v-if="item.icon === In" icon="chevron-double-right"></b-icon>
          <b-icon v-else-if="item.icon === Out" icon="chevron-double-left"></b-icon>
          <b-icon v-else icon="circle-small"></b-icon>
          <time :class="levelString(item.level)">{{ item.time }}</time>
          <code v-if="item.type === HTML" v-html="item.content"></code>
          <code v-else>{{ item.content }}</code>
        </li>
      </RecycleScroller>
    </main>
    <footer>detail</footer>
  </div>
</template>

<script lang="ts">
import { ConsoleModule } from '@/store/modules/console'
import { Component, Vue, Watch } from 'vue-property-decorator'
import { ContentType, IconType, Level, Log } from '@/store/types'

@Component
export default class Output extends Vue {
  HTML = ContentType.HTML
  Plain = ContentType.Plain
  In = IconType.In
  Out = IconType.Out

  selected = -1
  autoScroll = true

  get logs() {
    return ConsoleModule.logs
  }

  levelString(index: number) {
    return ['info', 'warning', 'error'][index]
  }

  @Watch("logs")
  onNewLog(logs: Log[]) {
    if (!this.autoScroll) return
    const div = this.$refs.logs as HTMLDivElement
    div.scrollTop = div.scrollHeight
  }

  select(id: number) {
    const highlight = (id: number, state: boolean) => {
      const item = this.logs[id]
      if (item) item.selected = state
    }

    if (this.selected > -1) {
      highlight(this.selected, false)
    }

    highlight(id, true)
    this.selected = id
  }

  mounted() {
    // mock
    if (true) {
      ConsoleModule.log({
        type: ContentType.HTML,
        icon: IconType.In,
        content: `<span><span class="mtk5">'hello&nbsp;'</span><span class="mtk1">&nbsp;</span><span class="mtk9">+</span><span class="mtk1">&nbsp;</span><span class="mtk22">Process</span><span class="mtk9">.</span><span class="mtk1">id</span></span>`
      })

      ConsoleModule.log({
        icon: IconType.Out,
        content: 'hello world'
      })

      for (let i = 0; i < 20; i++) {
        ConsoleModule.log({
          content: `hello world ${i}`
        })
      }

      ConsoleModule.log({
        level: Level.Error,
        content: 'Fatal error:'
      })

      const add = () => {
        ConsoleModule.log({
          level: Math.floor(Math.random() * 3),
          content: new Date().toString()
        })
        setTimeout(add, 200 + Math.random() * 1000)
      }

      add()      
    }

    // mock end
  }
}
</script>

<style lang="scss" scoped>
pre {
  padding: 0;
}

.container {
  display: flex;
  flex-direction: column;
  height: 100%;

  main.output {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
  }
}

li.log-item {
  list-style: none;
  display: flex;

  &.on {
    background: rgba(0, 0, 0, .3)
  }

  time {
    font-size: 0.75rem;
    width: 120px;
    margin: 2px;

    &.warning {
      color: yellow;
    }

    &.error {
      color: red;
    }
  }

  code {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }
}
</style>
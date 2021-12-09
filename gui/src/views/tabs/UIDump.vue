<template>
  <div class="uiview-frame">
    <main class="uiview-main">
      <ul :style="{ transform }" class="uiview-root uiview-subviews" ref="tree">
        <UIViewNode :node="root" />
      </ul>

      <!-- todo: -->
      <!-- <aside v-if="selected">
        <header>
          <h2>Node <b-button type="is-small" icon-left="close" @click="selected = undefined"></b-button></h2>
        </header>
      </aside> -->
    </main>

    <footer class="uiview-inspector-toolbar">
      <div class="slide">
        <b-slider :min="minScale" :max="maxScale" :step="step" v-model="scale" />
      </div>
      <b-button class="button" icon-left="content-copy" @click="copy" />
    </footer>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Base from './Base.vue'
import UIViewNode from '@/components/UIViewNode.vue'

@Component({
  components: {
    UIViewNode
  }
})
export default class UISnapShot extends Base {
  root = {}

  scale = 1
  maxScale = 10
  minScale = 0.2
  step = 0.02

  selected?: UIViewNode

  get transform(): string {
    return `scale(${this.scale}`
  }

  selectNode(node: UIViewNode) {
    if (this.selected) this.selected.selected = false
    this.selected = node
  }

  mounted() {
    this.title = `UI Dump - ${new Date().toLocaleString()}`
    this.loading = true
    this.$rpc.ui.dump().then((root: object) => {
      this.root = root
    }).finally(() => {
      this.loading = false
    })

    this.$on('selectNode', this.selectNode)
  }

  copy() {
    const el = this.$refs.tree as HTMLUListElement
    const selection = window.getSelection()
    if (!selection) {
      this.$buefy.toast.open({
        message: 'Warning: unable to copy data (selection unavaliable)',
        type: 'is-warning'
      })
      return
    }
    selection.removeAllRanges()
    const range = document.createRange()
    range.selectNode(el)
    selection.addRange(range)
    document.execCommand('copy')
    selection.removeAllRanges()
    this.$buefy.toast.open({
      message: 'Successfully copied to clipboard',
      type: 'is-success'
    })
  }
}
</script>

<style lang="scss">

.uiview-frame {
  display: flex;
  flex-direction: column;
}

.uiview-inspector-toolbar {
  padding: 10px;
  position: sticky;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: space-between;

  > .slide {
    width: 200px;
  }
}

.uiview {
  font-family: 'Fira Code', monospace;
}

.uiview-main {
  flex: 1;
  overflow: auto;
}

.uiview-root {
  margin-top: 10px;
  transform-origin: top left;
}

.uiview-subviews {
  p {
    transition: ease-in 0.2s background-color;
    white-space: nowrap;

    > a {
      margin: 0 6px;
      display: inline-block;
    }
  }

  p:hover {
    background: #00000030;

    .mdi {
      color: #ffffff;
    }

    span.description {
      color: #4caf50;
    }
  }

  .mdi {
    color: #ffffff74;
    margin-right: 4px;
    transition: ease-in-out 0.2s color;
  }

  span.description {
    margin-left: 4px;
    color: #ffffff74;

    .num {
      color: #5b8fb9;
    }

    .str {
      color: #ae4dd1;
    }

    .hex {
      color: #d4a312;
    }

    .bool {
      color: #61ad51;
    }

    .op {
      color: lightseagreen;
    }

    .clazz {
      cursor: cursor;
      color: #e91e63;
      &:hover {
        background: #000;
      }
    }
  }

  span.delegate {
    color: #b4af88;
    background: #1c1c1c;
    cursor: pointer;
    display: inline-block;
    margin-left: 1em;
    transition: ease-in-out 0.2s color;

    &:hover {
      color: #ffeb3b;
      background: #111;
    }
  }
}

</style>

<template>
  <div>
    <!-- <main class="uiview-main"> -->
      <ul :style="{ fontSize }" class="uiview-root uiview-subviews">
        <UIViewNode :node="root" />
      </ul>

      <!-- todo: -->
      <!-- <aside v-if="selected">
        <header>
          <h2>Node <b-button type="is-small" icon-left="close" @click="selected = undefined"></b-button></h2>
        </header>
      </aside> -->
    <!-- </main> -->

    <p class="uiview-inspector-toolbar">
      <input type="range" :min="minSize" :max="maxSize" :step="step" v-model="size" class="slider">
    </p>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Base from './Base.vue'
import UIViewNode from '../../components/UIViewNode.vue'

@Component({
  components: {
    UIViewNode
  }
})
export default class UISnapShot extends Base {
  root = {}
  size = 1.1

  maxSize = 2
  minSize = 0.5
  step = 0.1

  selected?: UIViewNode

  get fontSize() {
    return Math.pow(12, this.size) + 'px'
  }

  selectNode(node: UIViewNode) {
    if (this.selected) this.selected.selected = false
    this.selected = node
  }

  mounted() {
    this.loading = true
    this.$rpc.ui.dump().then((root: object) => {
      this.root = root
    }).finally(() => {
      this.loading = false
    })

    this.$on('selectNode', this.selectNode)
  }
}
</script>

<style lang="scss">

.uiview-inspector-toolbar {
  padding: 10px;
  position: sticky;
  bottom: 0;
  display: flex;
  align-items: center;
  justify-content: center;
}

.uiview {
  font-family: 'Fira Code', monospace;

//   &.selected > p {
//     background: #001b27;

//     &:hover {
//       background: #002f44;
//     }
//   }
}

.uiview-root {
  margin-top: 10px;
}

.uiview-subviews {
  p {
    transition: ease-in 0.2s background-color;
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

    .hex {
      color: #d4a312;
    }

    .op {
      color: lightseagreen;
    }

    .clazz {
      cursor: default;
      color: #e91e63;
    }
  }

  span.delegate {
    color: #b4af88;
    background: #333;
    cursor: pointer;
    display: inline-block;
    margin-left: 1em;
    transition: ease-in-out 0.2s color;

    &:hover {
      color: #ffeb3b;
      background: #444;
    }
  }
}

</style>

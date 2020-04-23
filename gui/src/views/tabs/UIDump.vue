<template>
  <div>
    <p class="uiview-inspector-toolbar" @mouseout="dismiss">
      <input type="range" :min="minSize" :max="maxSize" :step="step" v-model="size" class="slider">
    </p>

    <ul :style="{ fontSize }" class="uiview-root uiview-subviews">
      <UIViewNode :node="root" />
    </ul>
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

  get fontSize() {
    return Math.pow(12, this.size) + 'px'
  }

  mounted() {
    this.loading = true
    this.$rpc.ui.dump().then((root: object) => {
      this.root = root
    }).finally(() => {
      this.loading = false
    })
  }

  dismiss() {
    this.$rpc.ui.dismissHighlight()
  }
}
</script>

<style lang="scss">
// textarea {
//   font-family: monospace;
//   width: 100%;
//   height: calc(100% - 6px);
//   background: #222;
//   color: #d0d0d0;
//   padding: 20px;
//   outline: none;
// }

.uiview-inspector-toolbar {
  padding: 10px;
}

.uiview {
  font-family: monospace;
  // display: list-item;
  // list-style: square;
  cursor: pointer;
}

.uiview-subviews {
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
      color: #e91e63;
    }
  }

  p:active {
    outline: lightblue;
  }
}

</style>

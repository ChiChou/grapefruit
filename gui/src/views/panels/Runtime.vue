<template>
  <div class="runtime-panel">
    <header>
      <b-field position="is-centered">
        <b-input placeholder="Search..." type="search" icon="magnify" class="is-dark" v-model="keyword" />
      </b-field>
    </header>
    <main class="scroll">
      <ClassDump :keyword="keyword" />
    </main>
  </div>
</template>

<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'
import ClassDump from './ClassDump.vue'

@Component({
  components: {
    ClassDump
  }
})
export default class General extends Vue {
  keyword = ''
}
</script>

<style lang="scss" scoped>
.runtime-panel {
  display: flex;
  flex-direction: column;
  height: 100%;

  .scroll {
    overflow: auto;
    flex: 1;
  }
}

.control.is-dark > input.input {
  border-radius: 0 !important;
  background: #000;
  color: white;
}
</style>

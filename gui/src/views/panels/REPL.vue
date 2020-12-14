<template>
  <div>
    <b-progress class="thin" :class="{ show: loading }"></b-progress>
    <header>
      <h1>REPL</h1>
      <nav>
        <a @click="create"><b-icon icon="plus" /></a>
        <a @click="refresh"><b-icon icon="refresh" /></a>
      </nav>
    </header>

    <main>
      <ul class="scripts" :class="{ loading }">
        <li v-for="(file, i) in list" :key="i">
          <a @click="open(file)"><b-icon icon="language-javascript"/> {{ file }}</a>
        </li>
      </ul>
    </main>
  </div>
</template>

<script lang="ts">
import Axios from 'axios'
import { Component, Vue } from 'vue-property-decorator'

@Component({

})
export default class REPL extends Vue {
  list: string[] = []
  loading = false

  mounted() {
    this.refresh()
  }

  create() {
    this.$bus.$emit('openTab', 'CodeRunner', 'CodeRunner - new *')
  }

  open(file: string) {
    this.$bus.$emit('openTab', 'CodeRunner', `CodeRunner - ${file}`, { file })
  }

  refresh() {
    this.loading = true
    Axios.get('/snippets')
      .then(({ data }) => {
        this.list = data
      })
      .finally(() => {
        this.loading = false
      })
  }
}

</script>

<style lang="scss" scoped>
header {
  display: flex;

  h1 {
    flex: 1;
    padding: .5em;
  }

  nav {
    padding: .5em;

    > a {
      color: #999;
      &:hover {
        color: #fff;
      }
    }
  }
}

ul.scripts {
  padding: 4px 10px;
  transition: all ease-in .2s;

  opacity: 1;

  &.loading {
    opacity: 0;
  }
}
</style>

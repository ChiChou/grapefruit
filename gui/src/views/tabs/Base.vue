<script lang="ts">
import { Component, Vue } from 'vue-property-decorator'

@Component
export default class BaseTab extends Vue {
  private __loading = false

  set loading(state: boolean) {
    this.__loading = state
    this.$emit('update:loading', state)
  }

  get loading(): boolean {
    return this.__loading
    // throw Error('this property is not expected to be read')
  }

  mounted() {
    this.$parent.$on('resize', this.resize)
  }

  resize() {
    // intended to be implemented by subclasses
  }
}
</script>

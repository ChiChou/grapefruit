<script lang="ts">
import { Prop, Component } from 'vue-property-decorator'
import Base from './Base.vue'

@Component
export default class Preview extends Base {
  @Prop({ required: true })
  path!: string

  get extension(): string {
    const lastIndex = this.path.lastIndexOf('.')
    if (lastIndex === -1) return ''
    return this.path.substr(lastIndex + 1)
  }

  async link(): Promise<string> {
    this.loading = true
    try {
      const session = await this.$rpc.fs.download(this.path)
      return `/api/download/${session}`
    } finally {
      this.loading = false
    }
  }
}
</script>

<style scoped>
textarea {
  width: 100%;
  height: 100%;
  font-family: 'Fira Code', monospace;
  font-size: 1rem;
  background: #1b1b1b;
  padding: 10px;
  color: #eee;
}
</style>

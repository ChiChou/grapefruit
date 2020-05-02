<script lang="ts">
import { Prop, Component } from 'vue-property-decorator'
import Base from './Base.vue'

import { extname } from '../../utils'

@Component
export default class Preview extends Base {
  @Prop({ required: true })
  path!: string

  get extension(): string {
    return extname(this.path)
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

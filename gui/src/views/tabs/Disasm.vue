<template>
  <div class="pad">
    <ul v-if="disasm.length" class="disassembly">
      <li v-for="(insn, index) of disasm" :key="index">
        <span class="addr">{{ insn.address }}</span>
        <span class="mnemonic">{{ insn.mnemonic }}</span>
        <span
          v-if="insn.symbol"
          class="symbol"
          @click="$bus.$emit('openTab', 'Disasm', 'Disassembly: ' + insn.symbol, { addr: insn.operands[0].value })"
        >
          {{ insn.opStr }}
        </span>
        <Operand v-else class="op" :insn="insn" />
        <span v-if="insn.comment" class="comment">; {{ insn.comment }}</span>
      </li>
      <li class="more"><b-button @click="more"><span class="mdi mdi-autorenew"></span>More</b-button></li>
    </ul>
    <p v-else>Failed to load disassembly</p>
  </div>
</template>

<script lang="ts">
// eslint-disable-next-line
/// <reference path="../../frida.shim.d.ts" />

import { Prop, Component, Vue } from 'vue-property-decorator'
import Base from './Base.vue'
import { CreateElement } from 'vue'
import { tokenize } from '../../utils'

type Insn = ArmInstruction | Arm64Instruction;

interface Token {
  type: string;
  word: string;
}

interface Response {
  symbol: string;
  instructions: Insn[];
}

function * scan(str: string): IterableIterator<Token> {
  const delimiters = ', []#!'

  for (const token of tokenize(str, delimiters)) {
    let type = ''
    if (delimiters.includes(token)) {
      type = ''
    } else if (token.match(/^-?(0x)?[\da-fA-f]+/)) {
      type = 'num'
    } else if (token.match(/^([rx]\d+|\w+)$/)) {
      type = 'reg'
    } else {
      console.debug('unknown token', token)
    }
    yield {
      type,
      word: token
    }
  }
}

@Component
class Operand extends Vue {
  @Prop({ required: true })
  insn!: ArmInstruction | Arm64Instruction

  render(createElement: CreateElement) {
    return createElement(
      'span',
      {},
      [...scan(this.insn.opStr)].map(token => {
        return token.type ? createElement(
          'span',
          {
            attrs: {
              class: token.type
            }
          },
          [token.word]) : token.word
      })
    )
  }
}

@Component({
  components: {
    Operand
  }
})
export default class Disasm extends Base {
  @Prop({ required: true })
  addr!: string

  disasm: Insn[] = []
  loadingMore = false
  symbol?: string

  get cursor() {
    const last = this.disasm.pop()
    return last ? last.address : this.addr
  }

  mounted() {
    this.more()
  }

  more() {
    if (!this.disasm.length) this.loading = true
    this.loadingMore = true
    this.$rpc.disasm(this.cursor).then((response: Response) => {
      this.symbol = response.symbol
      this.disasm.push(...response.instructions)
    }).finally(() => {
      this.loading = false
      this.loadingMore = false
    })
  }
}
</script>

<style lang="scss">

.disassembly {
  font-family: "Fira Code", monospace;
  white-space: nowrap;
  font-size: 0.875rem;

  li {
    display: block;
  }

  span {
    display: inline-block;
  }

  .addr {
    color: #999;
    margin-right: 8em;
  }

  .comment {
    color: #ffffff78;
  }

  .mnemonic {
    color: white;
    width: 6em;
    text-transform: uppercase;
  }

  .op {
    color: #c0c0b0;
  }

  .num {
    color: #bc4531;
    font-weight: bold;
  }

  .reg {
    color: #73adad;
    text-transform: uppercase;
  }

  .more {
    display: block;
    > button {
      margin: 10px auto;
      width: 300px;
      display: block;
    }
  }

  .symbol {
    color: #ffd208;
    cursor: pointer;
  }
}

</style>

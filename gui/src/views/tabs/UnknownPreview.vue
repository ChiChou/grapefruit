<template>
  <div tabindex="0" @keydown="handleKey" class="xxd">
    <b-progress v-if="buffering" :value="progress" show-value format="percent" type="is-dark" class="thin" />

    <div class="file" v-if="dataView">
      <div class="offsets" title="Offset">
        <div class="offset" v-for="(offset, lineIndex) of offsets" :key="lineIndex"
          :class="{ 'active': isLineActive(lineIndex) }" @click="handleLineClick(lineIndex, $event)">{{ offset }}</div>
      </div>
      <div class="lines hex" title="Hex value">
        <div class="line" v-for="(line, lineIndex) of hex" :key="lineIndex" :class="{ 'active': isLineActive(lineIndex) }"
          @click="handleLineClick(lineIndex, $event)">
          <div class="value" v-for="(value, valueIndex) of line" :key="(lineIndex * 16) + valueIndex"
            :class="{ 'active': isValueActive(lineIndex, valueIndex) }" @click="handleValueClick(valueIndex, $event)">
            {{value}}</div>
        </div>
      </div>
      <div class="lines ascii" title="Ascii value">
        <div class="line" v-for="(line, lineIndex) of ascii" :key="lineIndex" :class="{ 'active': isLineActive(lineIndex) }"
          @click="handleLineClick(lineIndex, $event)">
          <div class="value" v-for="(value, valueIndex) of line" :key="(lineIndex * 16) + valueIndex"
            :class="{ 'active': isValueActive(lineIndex, valueIndex) }" @click="handleValueClick(valueIndex, $event)">
            {{value}}</div>
        </div>
      </div>
    </div>
  </div>
</template>

<script lang="ts">
/**
 * This component is based on
 * https://codepen.io/AzazelN28/pen/mQMapb
 */

import { Component } from 'vue-property-decorator'
import Preview from './Preview.vue'
import { rem2px } from '@/utils'

@Component
export default class UnknownPreview extends Preview {
  buffering = false
  progress = 0

  dataView: DataView | null = null
  rowLength = 16
  row = {
    start: 0,
    current: 0
  }

  column = 0
  height = 0
  lineHeight = 16

  get size() {
    return this.dataView?.byteLength || 0
  }

  get offset() {
    return (this.row.current * this.rowLength) + this.column
  }

  get maxStartRow() {
    return this.maxRows - (this.rows - 1)
  }

  get maxRows() {
    if (!this.dataView) return 0
    return Math.floor(this.dataView.byteLength / this.rowLength)
  }

  get rows() {
    return Math.floor(this.height / this.lineHeight) // NOTE: This is not the row length (it's the pixel height of each line)
  }

  get offsets() {
    if (!this.dataView) return []

    function * gen(this: UnknownPreview) {
      for (let row = this.row.start; row < this.row.start + this.rows; row++) {
        yield (row * this.rowLength).toString(16).padStart(8, '0')
      }
    }

    return [...gen.call(this)]
  }

  get hex() {
    return this.getRows((value: number) => value.toString(16).padStart(2, '0').toUpperCase())
  }

  get ascii() {
    return this.getRows((value: number) => value >= 32 && value <= 127 ? String.fromCharCode(value) : '.')
  }

  getRows(fn: (val: number) => string) {
    if (!this.dataView) return []

    const rows = []
    for (let row = this.row.start; row < this.row.start + this.rows; row++) {
      const values = []
      for (let column = 0; column < this.rowLength; column++) {
        const offset = row * this.rowLength + column
        const value = offset < this.dataView.byteLength ? this.dataView.getUint8(offset) : 0
        values.push(fn(value))
      }
      rows.push(values)
    }
    return rows
  }

  updateColumnToLine() {
    if (!this.dataView) return
    const offset = this.row.current * this.rowLength + this.column
    if (offset >= this.dataView.byteLength) {
      this.column = (this.dataView.byteLength % this.rowLength) - 1
    }
  }

  moveCharLeft() {
    this.column = Math.max(0, this.column - 1)
  }

  moveCharRight() {
    if (!this.dataView) return
    const newColumn = Math.min(this.rowLength - 1, this.column + 1)
    const offset = this.row.current * this.rowLength + newColumn
    if (offset < this.dataView.byteLength) {
      this.column = newColumn
    }
  }

  moveLineUp() {
    this.row.current = Math.max(0, this.row.current - 1)
    if (this.row.current < this.row.start) {
      this.row.start = this.row.current
    }
    this.updateColumnToLine()
  }

  moveLineDown() {
    this.row.current = Math.min(this.maxRows, this.row.current + 1)
    if (this.row.current > this.row.start + (this.rows - 1)) {
      this.row.start = this.row.current - (this.rows - 1)
    }
    this.updateColumnToLine()
  }

  movePageUp() {
    this.row.start = Math.max(0, this.row.start - this.rows)
    this.row.current = this.row.start
    this.updateColumnToLine()
  }

  movePageDown() {
    this.row.start = Math.min(this.maxStartRow, this.row.start + this.rows)
    this.row.current = this.row.start
    this.updateColumnToLine()
  }

  moveToStart() {
    this.row.current = this.row.start = 0
  }

  moveToEnd() {
    this.row.start = this.maxStartRow
    this.row.current = this.maxRows
  }

  goToChar(charIndex: number) {
    this.column = charIndex
  }

  goToLineRelative(lineIndex: number) {
    this.row.current = this.row.start + lineIndex
  }

  isValueActive(lineIndex: number, valueIndex: number) {
    if (!this.isLineActive(lineIndex)) {
      return false
    }
    return valueIndex === this.column
  }

  isLineActive(lineIndex: number) {
    return lineIndex === this.row.current - this.row.start
  }

  handleValueClick(valueIndex: number) {
    this.goToChar(valueIndex)
  }

  handleLineClick(lineIndex: number) {
    this.goToLineRelative(lineIndex)
  }

  handleKey(e: KeyboardEvent) {
    if (e.code === 'ArrowUp' || e.key === 'k') {
      this.moveLineUp()
    } else if (e.code === 'ArrowDown' || e.key === 'j') {
      this.moveLineDown()
    }

    if (e.code === 'ArrowLeft' || e.key === 'h') {
      this.moveCharLeft()
    } else if (e.code === 'ArrowRight' || e.key === 'l') {
      this.moveCharRight()
    }

    if (e.code === 'PageUp') {
      this.movePageUp()
    } else if (e.code === 'PageDown') {
      this.movePageDown()
    }

    if (e.key === 'g') {
      this.moveToStart()
    } else if (e.key === 'G') {
      this.moveToEnd()
    }
  }

  handleWheel(e: WheelEvent) {
    if (e.deltaY < 0) {
      this.moveLineUp()
    } else {
      this.moveLineDown()
    }
  }

  mounted() {
    this.lineHeight = rem2px(1.625)
    this.resize()
    this.loading = true
    this.load()
      .finally(() => {
        this.loading = false
      });

    (this.$el as HTMLDivElement).addEventListener('wheel', this.handleWheel)
  }

  beforeDestroy() {
    (this.$el as HTMLDivElement).removeEventListener('wheel', this.handleWheel)
  }

  async load() {
    const url = await this.link()
    this.buffering = true
    this.progress = 0

    const data = await new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest()
      xhr.open('GET', url)
      xhr.responseType = 'arraybuffer'
      xhr.onprogress = ev => {
        if (ev.total > 1024 * 1024 * 100) {
          reject(new Error('File too large'))
          xhr.abort()
        }
        this.progress = ev.loaded * 100 / ev.total
      }
      xhr.onload = () => resolve(xhr.response)
      xhr.onerror = () => reject(new Error(`xhr error: ${xhr.status} ${xhr.statusText}`))
      xhr.send()
    }) as ArrayBuffer

    this.dataView = new DataView(data)
    this.$nextTick(this.resize)
    this.buffering = false
  }

  resize() {
    this.height = this.$el.clientHeight
  }
}
</script>

<style lang="scss" scoped>
.file {
  display: flex;
  flex-direction: row;
  font-family:'Fira Code', monospace;
  font-size: 16px;
}

.drag {
  background: #333;
  color: #bbb;
  display: flex;
  align-items: center;
  justify-content: center;

  .open-file {
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 16rem 2rem;
    border: 2px dashed #bbb;
    border-radius: 1rem;

    label.open-file-label {
      font-size: 2rem;
      width: 100%;
      height: 100%;
      text-align: center;
    }
  }
}

.file, .drag, .offsets, .values, .interpreter {
  width: 100%;
  height: 100%;
}

.offsets {
  background: #222;
  color: #aaa;
  display: flex;
  flex-direction: column;
  align-items: flex-end;
  width: auto;

  .offset {
    margin-bottom: .125rem;
    padding: 0 1rem;
    &.active {
      background: #224;
      color: #bbf;
    }
  }
}

.lines {
  &.hex {
    background: #333;
    color: #bbb;
    display: flex;
    flex-direction: column;
    .line {
      margin-bottom: .125rem;
      display: flex;
      flex-direction: row;
      padding: 0 1rem;
      &.active {
        background: #336;
        color: #bbf;
      }
      .value {
        margin: 0 .5rem;
        &.active {
          background: #bbf;
          color: #336;
        }
      }
    }
  }

  &.ascii {
    background: #373737;
    color: #bbb;
    display: flex;
    flex-direction: column;
    .line {
      margin-bottom: .125rem;
      display: flex;
      flex-direction: row;
      padding: 0 1rem;
      &.active {
        background: #373766;
        color: #bbf;
      }
      .value {
        &.active {
          background: #fbf;
          color: #373766;
        }
      }
    }
  }
}

.xxd {
  height: 100%;
  // overflow: hidden;
}
</style>

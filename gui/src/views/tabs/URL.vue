<template>
  <div class="pad">
    <section class="playground">
      <textarea ref="input" class="input" v-model="payload" @keydown.enter.prevent="submit" autocomplete="off" />
      <button class="button is-primary" @click="submit" :disabled="busy">
        <span>Submit</span> &nbsp;
        <b-icon v-if="busy" icon="loading" custom-class="mdi-spin" />
        <b-icon v-else icon="send" />
      </button>
    </section>

    <ul class="url" v-for="(url, index) in urls" :key="index">
      <li>
        <h2>{{ url.name }} <b-tag v-if="url.role">{{ url.role }}</b-tag></h2>
        <article>
          <ul>
            <li v-for="(scheme, j) in url.schemes" :key="j" @click="test(scheme)">{{ scheme }}://</li>
          </ul>
        </article>
      </li>
    </ul>
  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import Base from './Base.vue'

interface Url {
  name: string;
  schemes: string[];
  role: string;
}

interface Response {
  urls: Url[];
}

@Component
export default class URLTab extends Base {
  urls: Url[] = []
  payload = ''
  history: string[] = []
  busy = false

  mounted() {
    this.loading = true
    this.$rpc.info
      .info()
      .then((data: Response) => {
        this.urls = data.urls
      })
      .finally(() => {
        this.loading = false
      })
  }

  test(scheme: string) {
    this.payload = `${scheme}://`;
    (this.$refs.input as HTMLInputElement).focus()
  }

  async submit() {
    this.busy = true
    this.history.push(this.payload)
    await this.$rpc.url.open(this.payload)
    this.busy = false
  }
}
</script>

<style lang="scss" scoped>
h1 {
  color: #ffffffa0;
}
ul.url {
  > li {
    display: block;

    > h2 {
      font-weight: 100;
      color: #ffc107;
    }

    > article {
      margin-bottom: 20px;

      > ul > li {
        padding-left: 1em;
        cursor: pointer;
        color: #959595;
        transition: ease-in-out 0.2s color;

        &:hover {
          color: #dfdfdf;
          text-decoration: underline;
        }
      }
    }
  }
}

.playground {
  margin: -20px -20px 10px -20px;
  position: sticky;
  top: 0;
  transition: none;
}

textarea, button.button {
  border-radius: 0;
  width: 100%;
  display: block;
}

textarea {
  background: #1b1b1b;
  color: #eee;
  border: 1px solid turquoise;
  padding: 1rem;
  font-family: monospace;
  min-height: 6em;
}

</style>

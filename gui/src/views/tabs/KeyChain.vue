<template>
  <div>
    <b-checkbox class="authenticator" :disabled="loading" v-model="faceid">Authenticate with FaceID or TouchID</b-checkbox>

    <b-table :data="keychain" narrowed hasDetails :loading="loading" default-sort="clazz" detailed>
      <template slot-scope="props">
        <b-table-column field="clazz" label="Class" sortable width="120">
          <b-tag>{{ props.row.clazz | trim('kSecClass') }}</b-tag>
        </b-table-column>

        <b-table-column field="account" label="Account" sortable>
          <span class="break-all">{{ props.row.account }}</span>
        </b-table-column>

        <b-table-column field="data" label="Data">
          <code class="break-all">{{ props.row.data }}</code>
        </b-table-column>

        <b-table-column field="accessibleAttribute" label="Accessible Attribute" width="180" sortable>
          <b-tag type="is-info">{{ props.row.accessibleAttribute | trim('kSecAttrAccessible') }}</b-tag>
        </b-table-column>
      </template>

      <template slot="detail" slot-scope="props">
        <article>
          <ul class="keychain-attributes">
            <li v-for="(title, key) in columns" :key="key">
              <dl>
                <dt>{{ title }}</dt>
                <dd>{{ props.row[key] }}</dd>
              </dl>
            </li>
          </ul>

        </article>
      </template>

      <div slot="empty" class="has-text-centered">
        <p v-show="!loading">Empty result</p>
      </div>
    </b-table>
  </div>
</template>

<script lang="ts">
import { Component, Watch } from 'vue-property-decorator'
import Base from './Base.vue'

@Component({
  filters: {
    trim(val, prefix) {
      if (!val) return ''
      return val.indexOf(prefix) === 0 ? val.substr(prefix.length) : val
    }
  }
})
export default class KeyChain extends Base {
  keychain: object[] = []
  columns: { [key: string]: string } = {}
  faceid = false

  @Watch('faceid')
  toggleFaceID(val, old) {
    if (val !== old) this.load(val)
  }

  mounted() {
    const columns = {}
    const keys = ['service', 'label', 'creation', 'modification', 'description', 'entitlementGroup',
      'comment', 'creator', 'type', 'scriptCode', 'alias', 'invisible',
      'negative', 'customIcon', 'accessControl', 'generic']
    keys.forEach(key => { this.columns[key] = key.replace(/([a-z](?=[A-Z]))/g, '$1 ') })

    this.load()
  }

  load(faceid = false) {
    this.loading = true
    this.$rpc.keychain.list(faceid)
      .then(data => { this.keychain = data })
      .finally(() => { this.loading = false })
  }
}
</script>

<style lang="scss">
.b-table .table tr.detail {
  background: #282f2f;
  box-shadow: inset 0 1px 3px #000000d6;
}

.authenticator {
  margin: 10px;
}

ul.keychain-attributes {
  display: flex;
  flex-wrap: wrap;
  li {
    display: inline-block;
    width: 360px;
    dl {
      margin-bottom: 12px;
      dt {
        font-size: .75rem;
        color: #888;
      }
      dd {
        min-height: 1em;
      }
    }
  }
}
</style>

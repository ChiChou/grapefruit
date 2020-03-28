<template>
  <div class="welcome">
    <header>
      <h1>
        <img src="../assets/logo.dark.svg" alt="Passionfruit" width="200" id="logo" />
      </h1>
      <h2 class="subtitle">Runtime app instruments for iOS</h2>
      <!-- <b-button @click="connect">Add Remote TCP</b-button> -->
      <aside class="menu">
        <p class="menu-label">
          Frida version: {{ version }}
        </p>

        <p class="menu-label">
          Devices <loading v-if="loadingDevices" class="is-pulled-right"></loading>
        </p>

        <ul class="menu-list">
          <li v-if="!devices.length"><b-icon icon="lan-disconnect" type="is-danger"></b-icon> No device found</li>
        </ul>
      </aside>
    </header>
  </div>
</template>

<script lang="ts">
import { Component, Vue, Prop } from 'vue-property-decorator'

@Component
export default class Welcome extends Vue {
  @Prop() version = '12.5'
  @Prop() devices = []

  connect() {
    // todo
  }
}
</script>

<style lang="scss">
.welcome {
  padding: 40px;
}

h1 {
  margin: 0;
  font-weight: 100;
}
</style>

<template>
  <div class="pad">
    <section class="content">
      This App has access to the following
      <a target="_blank" href="https://developer.apple.com/documentation/bundleresources/information_property_list/protected_resources?language=objc">
      Protected Resources</a> based on its Info.plist</section>

    <section v-for="(keys, category) in report" :key="category" class="box">
      <h2><b-icon :icon="icon(category)"/>{{ category }}</h2>
      <b-field grouped group-multiline>
        <div class="control" v-for="(description, key) in keys" :key="key">
          <b-taglist attached>
            <b-tag size="is-large">
              {{ key }}
            </b-tag>
            <b-tag size="is-large">
              <a target="_blank" :href="'https://developer.apple.com/documentation/bundleresources/information_property_list/' + key">
                <b-icon icon="launch"/>
              </a>
            </b-tag>        
          </b-taglist>
        </div>
      </b-field>
    </section>

  </div>
</template>

<script lang="ts">
import { Component } from 'vue-property-decorator'
import BaseTab from './Base.vue'

type Report = { [key: string]: { [key: string]: string } }

@Component
export default class Privacy extends BaseTab {
  report: Report = {}

  mounted() {
    this.title = 'Protected Resources Access'
    this.loading = true
    this.load().finally(() => {
      this.loading = false
    })
  }

  icon(group: string) {
    const mapping: { [key: string]: string } = {
      Bluetooth: 'bluetooth',
      Calendar: 'calendar-month',
      Camera: 'camera',
      Microphone: 'microphone',
      Contacts: 'contacts',
      Biometrics: 'face-recognition',
      GameCenter: 'gamepad-circle',
      Health: 'medical-bag',
      Home: 'home-assistant',
      Location: 'crosshairs-gps',
      Music: 'headphones',
      Motion: 'motion-sensor',
      Network: 'access-point-network',
      NFC: 'nfc',
      Photos: 'image',
      Tracking: 'google-analytics',
      Sensor: 'smoke-detector-alert',
      Siri: 'account-voice',
      Speech: 'settings-voice',
      TV: 'tv',
      WiFi: 'wifi',
    }

    return mapping[group]
  }

  async load() {
    this.report = (await this.$rpc.scanner.privacy()) as Report
  }
}
</script>

<style lang="scss" scoped>
</style>
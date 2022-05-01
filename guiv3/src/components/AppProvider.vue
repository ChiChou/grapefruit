<template>
  <n-config-provider :theme="darkTheme">
    <n-loading-bar-provider>
      <n-message-provider>
        <n-dialog-provider>
          <slot></slot>
        </n-dialog-provider>
      </n-message-provider>
    </n-loading-bar-provider>
    <n-global-style />
  </n-config-provider>
</template>

<script setup lang="ts">
import { defineComponent } from 'vue';
import { useOsTheme, darkTheme } from 'naive-ui'
import {
  NMessageProvider,
  NLoadingBarProvider,
  NDialogProvider,
  NConfigProvider,
  NGlobalStyle
} from 'naive-ui';

defineComponent({
  name: 'AppProvider',
  components: {
    NMessageProvider,
    NLoadingBarProvider,
    NDialogProvider,
    NConfigProvider,
    NGlobalStyle
  },
});
</script>
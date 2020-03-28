<template>
  <div id="app">
    <router-view></router-view>
  </div>
</template>

<style lang="stylus">
body
  min-width 768px
  min-height 768px
  margin 0
  padding 0

#app {
  font-family: sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  height: 100vh;
  margin: 0;
  padding: 0;
  display: flex;
  flex-direction: column;
}
</style>

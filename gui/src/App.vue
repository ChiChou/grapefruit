<template>
  <div id="app">
    <router-view></router-view>
  </div>
</template>

<style lang="scss">
body {
  margin: 0;
  padding: 0;
}

html.no-scroll {
  overflow-y: hidden;
}

#app {
  font-family: sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  margin: 0;
  padding: 0;
}

html {
  scrollbar-face-color: #646464;
  scrollbar-base-color: #646464;
  scrollbar-3dlight-color: #646464;
  scrollbar-highlight-color: #646464;
  scrollbar-track-color: #333;
  scrollbar-arrow-color: #333;
  scrollbar-shadow-color: #646464;
  scrollbar-dark-shadow-color: #646464;
}

::-webkit-scrollbar { width: 10px; height: 10px;}
::-webkit-scrollbar-button { background-color: #666; display: none }
::-webkit-scrollbar-track { background-color: #646464;}
::-webkit-scrollbar-track-piece { background-color: #333; }
::-webkit-scrollbar-thumb { background-color: #666; border-radius: 5px; }
::-webkit-scrollbar-corner { background-color: #333; display: none; }
::-webkit-resizer { background-color: #666;}
</style>

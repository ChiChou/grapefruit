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

::-webkit-scrollbar {
  width: 10px;
  height: 10px;
}
::-webkit-scrollbar-button {
  background-color: #666;
  display: none;
}
::-webkit-scrollbar-track {
  background-color: #646464;
}
::-webkit-scrollbar-track-piece {
  background-color: #333;
}
::-webkit-scrollbar-thumb {
  background-color: #666;
  border-radius: 5px;
}
::-webkit-scrollbar-corner {
  background-color: #333;
  display: none;
}
::-webkit-resizer {
  background-color: #666;
}

.box:not(:last-child),
.content:not(:last-child),
.notification:not(:last-child),
.progress:not(:last-child),
.table:not(:last-child),
.table-container:not(:last-child),
.title:not(:last-child),
.subtitle:not(:last-child),
.block:not(:last-child),
.highlight:not(:last-child),
.breadcrumb:not(:last-child),
.level:not(:last-child),
.list:not(:last-child),
.message:not(:last-child),
.tabs:not(:last-child) {
  margin-bottom: 0.5rem;
}

.b-tabs:not(:last-child) {
  margin-bottom: 0.5rem;
}

.b-tabs.is-fullwidth.header-only .tab-content{
  display: none;
}
</style>

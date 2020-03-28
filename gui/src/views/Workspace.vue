<template>
  <div>
    <section class="workspace">
      <split-pane :min-percent="10" :default-percent="15" split="vertical">
        <template slot="paneL"></template>
        <template slot="paneR">
          <split-pane split="horizontal" :default-percent="80">
            <template slot="paneL"></template>
            <template slot="paneR"></template>
          </split-pane>
        </template>
      </split-pane>
    </section>
    <footer class="status">Establishing connection</footer>
  </div>
</template>

<style lang="scss">
.workspace {
  flex:1;
}

footer.status {
  background: #4caf50;
  padding: 4px;
  color: #fff;
  font-size: 12px;
}
</style>
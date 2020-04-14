<template>
  <div class="workspace">
    <main>
      <header class="action-bar">
        <nav>
          <ul>
            <li>
              <b-icon size="is-medium" icon="hexagon-multiple"></b-icon>
            </li>
            <li>
              <b-icon size="is-medium" icon="account"></b-icon>
            </li>
            <li>
              <b-icon size="is-medium" icon="home"></b-icon>
            </li>
            <li>
              <b-icon size="is-medium" icon="view-dashboard"></b-icon>
            </li>
          </ul>
        </nav>
      </header>

      <split-pane :min-percent="10" :default-percent="15" split="vertical" class="main-pane">
        <template slot="paneL">
          <div class="zone zone-treeview">treeview</div>
        </template>
        <template slot="paneR">
          <split-pane split="horizontal" :default-percent="80" :min-percent="20">
            <template slot="paneL">
              <div class="zone zone-editor">editor</div>
            </template>
            <template slot="paneR">
              <div class="zone zone-terminal">terminal</div>
            </template>
          </split-pane>
        </template>
      </split-pane>
    </main>
    <footer class="status">
      <div class="connecting"><b-icon icon="check-network" size="is-small"></b-icon>frida@12.8.20, iOS 13.3 - Messages</div>
    </footer>
  </div>
</template>

<style lang="scss">
.workspace {
  display: flex;
  flex-direction: column;
  height: 100vh;
}

main {
  flex: 1;
  display: flex;
  flex-direction: row;

  .action-bar {
    background: #282f2f;
    nav li {
      padding: 1rem;
    }
  }

  .main-pane {
    flex: 1;
  }
}

footer.status {
  font-size: 12px;
  background: #505050;

  .connecting {
    background: #068068;
    display: inline-block;
    padding: 2px 4px;
    color: #fff;
  }
}

.zone {
  padding: 20px;
  height: 100%;
  width: 100%;

  &.zone-treeview {
    background: #343c3d;
  }

  &.zone-terminal {
    background: #151515;
  }

  &.zone-editor {
    background: #2a2a2a;
  }
}
</style>

<template>
  <header class="action-bar">
    <nav class="side-nav">
      <ul>
        <li>
          <router-link to="general">
            <b-icon size="is-medium" icon="view-dashboard"></b-icon>
          </router-link>
        </li>
        <li>
          <router-link to="runtime">
            <b-icon size="is-medium" icon="hammer-wrench"></b-icon>
          </router-link>
        </li>
        <li>
          <router-link to="storage">
            <b-icon size="is-medium" icon="safe-square-outline"></b-icon>
          </router-link>
        </li>
        <li>
          <router-link to="files">
            <b-icon size="is-medium" icon="folder-home-outline"></b-icon>
          </router-link>
        </li>
      </ul>
    </nav>
  </header>
</template>

<script>
export default {}
</script>

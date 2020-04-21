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
            <b-icon size="is-medium" icon="code-braces"></b-icon>
          </router-link>
        </li>
        <li>
          <router-link to="hook">
            <b-icon size="is-medium" icon="bug-check-outline"></b-icon>
          </router-link>
        </li>
        <li>
          <router-link to="repl">
            <b-icon size="is-medium" icon="code-greater-than"></b-icon>
          </router-link>
        </li>
        <li>
          <router-link to="files">
            <b-icon size="is-medium" icon="apple-finder"></b-icon>
          </router-link>
        </li>
      </ul>
    </nav>
  </header>
</template>

<script>
// supress linter error
export default {}
</script>

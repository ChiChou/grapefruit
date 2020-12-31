<template>
  <header class="action-bar">
    <nav class="side-nav">
      <ul>
        <li>
          <router-link to="general">
            <b-icon size="is-medium" icon="view-dashboard" />
          </router-link>
        </li>
        <li>
          <router-link to="classes">
            <b-icon size="is-medium" icon="code-braces" />
          </router-link>
        </li>
        <li>
          <router-link to="modules">
            <b-icon size="is-medium" icon="cog-clockwise" />
          </router-link>
        </li>
        <!-- <li>
          <router-link to="hook">
            <b-icon size="is-medium" icon="bug-check-outline" />
          </router-link>
        </li> -->
        <li>
          <router-link to="repl">
            <b-icon size="is-medium" icon="code-greater-than" />
          </router-link>
        </li>
        <li>
          <router-link to="files">
            <b-icon size="is-medium" icon="apple-finder" />
          </router-link>
        </li>
        <li>
          <router-link to="resolver">
            <b-icon size="is-medium" icon="toy-brick-search-outline" />
          </router-link>
        </li>
        <li>
          <router-link to="webviews">
            <b-icon size="is-medium" icon="apple-safari" />
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

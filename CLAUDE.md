Monorepo with three workspaces:

- root (server), 
- `agent/` (Frida agent), 
- `gui/` (frontend).

## Static checks

All code changes must pass the relevant checks before committing.

### agent/ (Frida agent)

```sh
cd agent && bun run build    # full build (agents + types)
cd agent && bun run type     # type-check only (droid + fruity)
```

### gui/ (frontend)

```sh
cd gui && bun run lint       # Oxlint
cd gui && bunx tsgo --noEmit # type-check
cd gui && bun run build      # full build
```

### root (server)

```sh
bunx tsgo --noEmit  # type-check
bun test            # run tests
```

`bun run prepare` build everything at once, slow

## Skills

Install skills for Claude Code:

```sh
igf setup           # install to .claude/skills/ in current project
igf setup --global  # install to ~/.claude/skills/ for all projects
```

Available skills:

- `/igf` — CLI interface for the IGF server. Exposes all REST API and agent RPC.
- `/audit` — Autonomous mobile security audit aligned with OWASP MASTG v2.

## Code Style

Do not generate code splitter comments (or code dividers/dividers)

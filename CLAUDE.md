Monorepo with three workspaces:

- root (server),
- `agent/` (Frida agent),
- `gui/` (frontend).

## First-time setup

```sh
bun run setup      # install all deps, build agent, gui, fetch/build WASM assets
```

## Development

```sh
bun run dev        # server with watch
bun run dev:both   # tmux: server + gui dev
bun run dev:all    # tmux/wt: agent watch + gui dev + server dev
```

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

Prefer short symbol names. Do not repeat the module name in exported functions (e.g. `ansi.toHtml` not `ansi.ansiToHtml`). Drop noise words like "get", "create", "find" when the meaning is clear from context. Use import aliases to resolve name conflicts instead of making names longer.

## git

Do not automatically commit unless I ask

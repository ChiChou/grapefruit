Monorepo with three workspaces:

- root (server),
- `agent/` (Frida agent),
- `gui/` (frontend).

## First-time setup

```sh
npm run setup      # install all deps, build agent, gui, fetch/build WASM assets
```

## Development

```sh
npm run dev        # server with watch
npm run dev:both   # tmux: server + gui dev
npm run dev:all    # tmux/wt: agent watch + gui dev + server dev
```

## Static checks

All code changes must pass the relevant checks before committing.

### agent/ (Frida agent)

```sh
cd agent && npm run build    # full build (agents + types)
cd agent && npm run type     # generate/check agent types
```

### gui/ (frontend)

```sh
cd gui && npm run lint              # Oxlint
cd gui && npm exec tsgo -- --noEmit # type-check
cd gui && npm run build             # full build
```

### root (server)

```sh
npm exec tsgo -- --noEmit # type-check
npm test                   # run tests
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

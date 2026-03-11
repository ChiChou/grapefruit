# Development Setup & Workflow

## Prerequisites

- [Bun](https://bun.sh/) (primary runtime, recommended)
- Node.js >= 22.18.0 (alternative runtime for npm package)
- A device running [frida-server](https://frida.re/docs/installation/) connected via USB or network
- iOS or Android target device/emulator

## Installation

```bash
# Clone the repository
git clone https://github.com/chichou/grapefruit.git
cd grapefruit

# Install all dependencies (root + agent + gui)
bun install
```

Each workspace has its own `package.json`. The root `prepare` script handles building the agent and GUI automatically after install.

## Available Scripts

### Root

| Script                       | Description                                   |
| ---------------------------- | --------------------------------------------- |
| `bun run dev:both`           | Start backend + frontend dev servers together |
| `bun run dev`                | Backend only with file watching (`--watch`)   |
| `bun run start`              | Start backend without watch                   |
| `bun test`                   | Run tests with Bun test runner                |
| `bun run test:coverage`      | Run tests with LCOV coverage output           |
| `bun run test:coverage:text` | Run tests with text coverage summary          |
| `bun run build:cli`          | Build single executable for current platform  |
| `bun run build:npm`          | Build npm distribution package                |
| `bun run build:all`          | Cross-compile for all platforms               |

### Agent (`agent/`)

| Script                    | Description                                  |
| ------------------------- | -------------------------------------------- |
| `bun run build`           | Build all agents + types                     |
| `bun run build:fruity`    | Build iOS agent only                         |
| `bun run build:droid`     | Build Android agent only                     |
| `bun run build:transport` | Build transport layer                        |
| `bun run watch:fruity`    | Build iOS agent in watch mode                |
| `bun run watch:droid`     | Build Android agent in watch mode            |
| `bun run type`            | Generate TypeScript definitions for frontend |
| `bun run lint`            | Lint agent source                            |

### GUI (`gui/`)

| Script            | Description                         |
| ----------------- | ----------------------------------- |
| `bun run dev`     | Vite dev server                     |
| `bun run build`   | Production build (typecheck + Vite) |
| `bun run lint`    | Lint frontend source                |
| `bun run preview` | Preview production build locally    |

## Environment Variables

| Variable        | Default                             | Description                                       |
| --------------- | ----------------------------------- | ------------------------------------------------- |
| `FRIDA_VERSION` | `17`                                | Frida version to use (`16` or `17`)               |
| `HOST`          | `localhost` (prod) / hostname (dev) | Server bind address                               |
| `PORT`          | `31337`                             | Server port                                       |
| `BACKEND_PORT`  | `31337`                             | Backend port (dev mode only)                      |
| `WEB_PORT`      | `3000` (dev) / same as PORT (prod)  | Frontend port                                     |
| `FRIDA_TIMEOUT` | `1000`                              | Device discovery timeout (ms)                     |
| `NODE_ENV`      | —                                   | `development` or `production`                     |
| `SQLITE`        | —                                   | Set to `better-sqlite3` for Node.js compatibility |
| `PROJECT_DIR`   | `.igf` in current working directory | Data directory (database, cache, logs)             |

CLI arguments (`--frida`, `--host`, `--port`, `--project`) take precedence over environment variables.

## Build Targets

### CLI Binary (Bun SEA)

Single executable application using Bun's `--compile` flag:

```bash
# Current platform
bun run build:cli

# Cross-compile all platforms
bun run build:all
```

Outputs to `build/Release/`:

- `igf-linux-x64`
- `igf-windows-x64.exe`
- `igf-darwin-x64`
- `igf-darwin-arm64`

The build process:

1. Compiles agent and GUI
2. Creates `assets.tgz` (GUI dist, agent dist, Drizzle migrations)
3. Prebuilds native Frida modules for each target
4. Produces standalone binaries via `bun build --compile`

### npm Package

```bash
bun run build:npm
# or
npm pack
```

Bundles with `tsdown`, uses `better-sqlite3` for Node.js compatibility. The package includes a `bin/igf` entry point.

## Testing

Tests use Bun's built-in test runner.

```bash
# Run all tests
bun test

# With text coverage summary
bun run test:coverage:text

# With LCOV output (for CI)
bun run test:coverage
```

Test files live in `src/tests/`:

- `app.test.ts` — HTTP API tests
- `agent.test.ts` — Agent integration tests
- `ws.test.ts` — Socket.IO session tests

Coverage output goes to `coverage/lcov.info`.

## Development Tips

- The dev server (`bun run dev:both`) starts the backend on port 31337 and the Vite frontend on port 3000. The frontend proxies `/api` and `/socket.io/` to the backend.
- When working on the agent only, use `bun run watch:fruity` or `bun run watch:droid` for live rebuilds.
- Agent RPC can be tested directly with Frida CLI:
  ```bash
  frida -U -F -l agent/src/fruity/index.ts \
    -e 'rpc.exports.invoke("info", "processInfo", [])' -q
  ```
- Data (logs, database, cache) is stored in `.igf/` under the current working directory by default. Use `--project <path>` or the `PROJECT_DIR` environment variable to override.

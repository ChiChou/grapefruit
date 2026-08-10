# Development Setup & Workflow

## Prerequisites

- Node.js >= 22.18.0 with npm
- [wasi-sdk](https://github.com/WebAssembly/wasi-sdk) (optional, for building `r2hermes.wasm`)
- A device running [frida-server](https://frida.re/docs/installation/) connected via USB or network
- iOS or Android target device/emulator

## Installation

```bash
# Clone the repository
git clone https://github.com/chichou/grapefruit.git
cd grapefruit

# Install all dependencies, initialize submodules, fetch/build WASM assets
npm run setup
```

Each workspace has its own `package.json`. The root `setup` script installs dependencies for the root, `agent/`, and `gui/`, fetches the radare2 WASM asset, and builds `r2hermes.wasm` when wasi-sdk is available.

If the `r2hermes.wasm` step is skipped because wasi-sdk is missing, the Hermes bytecode decompiler will be unavailable until you run:

```bash
cd externals/radare/r2hermes.wasm
npm run setup
npm run build
```

## Available Scripts

### Root

| Script                       | Description                                   |
| ---------------------------- | --------------------------------------------- |
| `npm run setup`              | Install deps, initialize submodules, fetch/build WASM assets |
| `npm run dev:both`           | Start backend + frontend dev servers together |
| `npm run dev:all`            | Start agent watchers + backend + frontend     |
| `npm run dev`                | Backend only with file watching (`--watch`)   |
| `npm run start`              | Start backend without watch                   |
| `npm test`                   | Run tests with the Node.js test runner        |
| `npm run test:coverage`      | Run tests with LCOV coverage output           |
| `npm run test:coverage:text` | Run tests with text coverage summary          |
| `npm run build:cli`          | Build a single executable for the current platform |
| `npm run build:npm`          | Build npm distribution package                |

### Agent (`agent/`)

| Script                    | Description                                  |
| ------------------------- | -------------------------------------------- |
| `npm run build`           | Build all agents + types                     |
| `npm run build:fruity`    | Build iOS agent only                         |
| `npm run build:droid`     | Build Android agent only                     |
| `npm run build:transport` | Build transport layer                        |
| `npm run watch:fruity`    | Build iOS agent in watch mode                |
| `npm run watch:droid`     | Build Android agent in watch mode            |
| `npm run type`            | Generate TypeScript definitions for frontend |
| `npm run lint`            | Lint agent source                            |

### GUI (`gui/`)

| Script            | Description                         |
| ----------------- | ----------------------------------- |
| `npm run dev`     | Vite dev server                     |
| `npm run build`   | Production build (typecheck + Vite) |
| `npm run lint`    | Lint frontend source                |
| `npm run preview` | Preview production build locally    |

## Environment Variables

| Variable        | Default                             | Description                                       |
| --------------- | ----------------------------------- | ------------------------------------------------- |
| `FRIDA_VERSION` | `17`                                | Frida version to use (`16` or `17`)               |
| `HOST`          | `127.0.0.1`                         | Server bind address                               |
| `PORT`          | `31337`                             | Server port                                       |
| `BACKEND_PORT`  | `31337`                             | Backend port when `NODE_ENV=development`          |
| `FRIDA_TIMEOUT` | `1000`                              | Device discovery timeout (ms)                     |
| `NODE_ENV`      | —                                   | `development` or `production`                     |
| `PROJECT_DIR`   | `.igf` in current working directory | Data directory (database, cache, logs)             |
| `NO_OPEN`       | —                                   | Set to `1` to avoid opening a browser on startup   |

CLI arguments (`--frida`, `--host`, `--port`, `--project`) take precedence over their matching environment variables. `BACKEND_PORT` is a development-mode override.

## Build Targets

### CLI Binary (Node.js SEA)

Build a [Node.js single executable application](https://nodejs.org/api/single-executable-applications.html) for the current platform:

```bash
# Current platform
npm run build:cli
```

This requires an SEA-enabled Node.js 26 build, such as an official standalone Node.js binary.

Outputs to `build/Release/`:

- `igf-linux-x64`
- `igf-windows-x64.exe`
- `igf-darwin-arm64`

Release CI runs this command with Node.js 26 on native Linux, Windows, and Apple Silicon macOS runners. The local build process:

1. Fetches the radare2 WASM asset
2. Bundles the server and JavaScript dependencies into a single CommonJS entry with `tsdown`
3. Embeds the GUI, agent, Drizzle migrations, skills, radare2 WASM, and native addons as SEA assets
4. Builds the executable directly with `node --build-sea`
5. Signs the result on macOS

### npm Package

```bash
npm run build:npm
# or
npm pack
```

Bundles with `tsdown` and exposes the `igf` binary from `dist/bin.mjs`.

## Testing

Tests use Node.js's built-in test runner. Coverage is collected with `c8`.

```bash
# Run all tests
npm test

# With text coverage summary
npm run test:coverage:text

# With LCOV output (for CI)
npm run test:coverage
```

Test files live in `src/tests/`:

- `app.test.ts` — HTTP API tests
- `agent.test.ts` — Agent integration tests
- `ws.test.ts` — Socket.IO session tests

Coverage output goes to `coverage/lcov.info`.

## Development Tips

- `npm run dev:both` starts the backend on port 31337 and the Vite frontend on Vite's printed local URL. The frontend proxies `/api`, `/socket.io/`, and `/radare2.wasm` to the backend.
- When working on the agent only, use `npm run watch:fruity` or `npm run watch:droid` for live rebuilds.
- Agent RPC can be tested directly with Frida CLI:
  ```bash
  cd agent
  npm run build:fruity
  frida -U -F -l dist/fruity.js \
    -e 'rpc.exports.invoke("info", "processInfo", [])' -q
  ```
- Data (logs, database, cache) is stored in `.igf/` under the current working directory by default. Use `--project <path>` or the `PROJECT_DIR` environment variable to override.

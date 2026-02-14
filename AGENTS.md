# igf

## Project Structure

```
igf/
├── agent/          Frida agent injected into target processes
│   ├── types/
│   │   ├── fruity/ iOS-specific modules
│   │   ├── droid/  Android-specific modules
│   │   ├── common/ Shared modules (symbol, syslog, memory, sqlite, native)
│   │   └── lib/    Agent utility libraries
│   └── src/        Agent entry point and RPC dispatcher
├── gui/            React + TypeScript + Vite web frontend
│   └── src/
│       ├── components/  UI components (shadcn/ui based)
│       ├── lib/         Hooks, queries, RPC helpers
│       └── types/       Shared type declarations
├── src/            Backend server (Hono + Socket.IO)
│   ├── app.ts      HTTP API setup and route mounting
│   ├── ws.ts       WebSocket session management
│   ├── routes/     Route handlers (devices, transfer, data)
│   ├── lib/
│   │   ├── store/  Database modules (db, hooks, crypto, requests, preferences)
│   │   ├── log-writer.ts   File-based log writer
│   │   ├── middleware.ts   Shared Hono middleware
│   │   ├── serializer.ts  Frida object serializers
│   │   ├── schema.ts      Drizzle ORM schema
│   │   └── env.ts         Runtime configuration
│   └── tests/      Server-side tests
├── drizzle/        Database migrations
├── scripts/        Build and dev scripts
└── bin/            CLI entry point
```

## Platforms

Two target platforms: `fruity` (iOS) and `droid` (Android), with two modes: `app` and `daemon`.

Both platforms share common agent modules. The RPC proxy throws if you call a platform-specific API on the wrong platform.

## Tech Stack

- **Runtime**: Bun (preferred) or Node.js >= 22
- **Backend**: Hono (HTTP) + Socket.IO (WebSocket)
- **Frontend**: React + Vite + shadcn/ui + TanStack Query
- **Database**: SQLite via Drizzle ORM (bun:sqlite or better-sqlite3)
- **Agent**: Frida TypeScript agent compiled per platform

## Guidelines for Code Agents

Default to using Bun instead of Node.js.

- Use `bun <file>` instead of `node <file>` or `ts-node <file>`
- Use `bun test` instead of `jest` or `vitest`
- Use `bun install` instead of `npm install`
- Use `bun run <script>` instead of `npm run <script>`
- Bun automatically loads .env, so don't use dotenv

### Conventions

- Store modules use short method names: `append`, `query`, `count`, `rm`, `set`, `get`, `purge`
- Consumers use namespace imports: `import * as hookStore from "../lib/store/hooks.ts"`
- GUI uses `useRpcQuery` / `useRpcMutation` for platform-specific RPC calls
- Platform-aware components check `platform === Platform.Droid` and pick the correct API
- Build GUI: `cd gui && bun run build` (runs `tsc -b && vite build`)
- Run tests: `bun test`

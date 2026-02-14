# Grapefruit

> **Warning**: This project is under active development and is not ready for production use.

Runtime mobile application instrumentation toolkit powered by [Frida](https://frida.re). Inspect, hook, and modify iOS and Android apps through a web-based interface.

## Features

- Common pentest toolkit
  - iOS: KeyChain, WebKit and JavaScriptCore, CoreLocation, Binary Cookie, Property List Viewer, etc.
  - Android: To be added
- Runtime method hooking with structured logging
- Cryptographic API interception
- HTTP/HTTPS traffic capture
- Filesystem browser with upload and download
- SQLite database inspection
- Syslog streaming

## Prerequisites

- [Bun](https://bun.sh/) (recommended)
- A device running [frida-server](https://frida.re/docs/installation/) (USB or network)

I also try to make the npm package work under Node.js, but Bun is the primary target.

## Quick Start

```bash
# Install dependencies
bun install

# Start dev server (backend + frontend)
bun run dev:both
```

Then open `http://localhost:31337` in your browser.

## Project Structure

```
agent/    Frida agent (TypeScript, compiled per platform)
gui/      Web frontend (React + Vite + shadcn/ui)
src/      Backend server (Hono + Socket.IO)
drizzle/  Database migrations
```

## Building

```bash
# Build CLI binary (single executable)
bun run build:cli

# Build for npm distribution
bun run build:npm

# Build for all platforms
bun run build:all
```

## Development

```bash
# Backend only (with watch)
bun run dev

# Run tests
bun test

# Run tests with coverage
bun run test:coverage
```

## License

[MIT](LICENSE)

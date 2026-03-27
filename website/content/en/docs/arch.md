# Architecture Design

This page covers the design decisions and implementation details that make Grapefruit work — for users who want to understand how it functions under the hood.

## Why a Browser UI?

Traditional mobile security tools run in the terminal. Grapefruit uses a browser because it solves several problems:

**Cross-platform by default** — Frida works over USB or TCP to iOS and Android. The browser UI runs on your workstation (macOS, Windows, Linux) without any additional setup on the device.

**Rich interaction** — Interactive controls, syntax-highlighted code, hex dumps, and collapsible trees are awkward in a terminal. The browser gives you proper widgets without bundling a GUI toolkit.

**Multi-window workspace** — The dockable panel layout lets you arrange disassembly, hook logs, and terminal views side by side — something terminal multiplexers handle poorly.

## Three-Layer Architecture

```
Browser (React) ←→ Server (Node.js/Bun) ←→ Device (Frida Agent)
```

- **Frontend** — React SPA. Communicates with the server over Socket.IO for real-time events and REST for file transfers.
- **Server** — Manages Frida sessions, proxies RPC calls between frontend and agent, and stores hook/crypto/network logs in SQLite.
- **Agent** — TypeScript code injected into the target app. Exposes modules for inspection, hooking, and data extraction via Frida's RPC mechanism.

## Frida Agent Design

### Two Agents, One Pattern

Grapefruit ships two separate agents — one for iOS (`fruity`) and one for Android (`droid`). Each is compiled from TypeScript using `frida-compile` and loaded into the target process separately.

Despite the platform split, both agents share the same RPC pattern:

```typescript
rpc.exports = {
  invoke(namespace, method, args)   // Routes to the right module
  interfaces()                      // Lists all available methods
  restore(rules)                    // Re-applies saved hooks on reconnect
  snapshot()                        // Captures active hooks for persistence
}
```

### Module Registry

Each agent defines a static router that maps namespace names to module objects:

```typescript
// fruity/router.ts
export default { checksec, classdump, cookies, crypto, fs, keychain, ... }
```

When `invoke("fs", "ls", ["/"])` is called, the registry looks up `route.fs.ls` and invokes it. This keeps the RPC surface flat and extensible — adding a new module only requires registering it in the router.

### Type Sharing

Agent method signatures are defined in TypeScript. After build, `tsgo` generates type definitions that the frontend imports directly. The RPC proxy wraps these as async promises, so calling `rpc.fs.ls("/")` in the frontend is fully type-checked against the actual agent implementation.

## Analysis Engine

### radare2 in the Browser

Native code disassembly runs radare2 as a WebAssembly module on the server. This avoids shipping a native binary alongside the tool — the WASM build handles ARM/x86 disassembly, control flow graphs, and DEX analysis without platform-specific dependencies.

For live processes, memory pages are fetched from the target on demand as analysis discovers new basic blocks. This lets you begin examining code immediately rather than waiting for a full memory dump.

### Hermes Bytecode

React Native apps compiled with Hermes use a proprietary bytecode format. Grapefruit intercepts Hermes bytecode at runtime and uses [r2hermes](https://github.com/radareorg/r2hermes) — a C11 library — to disassemble and generate pseudocode. For AI decompilation, both the raw bytecode and generated pseudocode are sent to the LLM, giving it two views to cross-reference.

## Data Storage

Grapefruit does not use a project or workspace concept — all data is stored globally and disambiguated by device ID and target bundle/PID. This keeps the UI simple but means sessions for different apps share the same storage directory.

Hook logs, crypto traces, network requests, and JNI traces are stored in SQLite via Drizzle ORM. Pin (hook rule) snapshots are stored as JSON files for fast reloading.

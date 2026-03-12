# RPC Design

## Overview

igf uses a 3-layer communication architecture:

```
UI (React)  ←──Socket.IO / REST──→  Server (Hono)  ←──Frida RPC──→  Agent (in-process)
```

- **UI ↔ Server**: Socket.IO for real-time RPC and events, REST for data queries and file transfers
- **Server ↔ Agent**: Frida's `script.exports` RPC mechanism over USB/network

## Agent RPC Exports

Every platform agent (fruity/droid) exports four methods via `rpc.exports`:

### `invoke(namespace, method, args)`

The primary dispatch function. Routes calls through the module registry:

```typescript
// Example: list files in root directory
script.exports.invoke("fs", "ls", ["/"])

// Example: dump keychain items (iOS)
script.exports.invoke("keychain", "list", [])
```

### `interfaces()`

Returns an array of all available `namespace.method` strings:

```typescript
script.exports.interfaces()
// → ["checksec.all", "checksec.single", "classdump.hierarchy", "fs.ls", "fs.read", ...]
```

### `restore(rules)`

Restores previously saved hook rules (pins). Called automatically on session start to re-establish hooks from a prior session:

```typescript
script.exports.restore([
  { category: "objc", symbol: "-[NSURLSession dataTaskWithRequest:]", ... }
])
```

### `snapshot()`

Captures the current set of active hook rules for persistence:

```typescript
const rules = script.exports.snapshot()
// → [{ category: "objc", symbol: "...", ... }, ...]
```

## Registry Pattern

The registry is defined in `agent/src/common/registry.ts`:

```typescript
function createRegistry(route) {
  function invoke(ns, fn, args) {
    const iface = route[ns]
    if (!iface) throw new Error(`${ns} not found`)
    const method = iface[fn]
    if (!method) throw new Error(`${ns}.${fn} not found`)
    return method(...args)
  }

  function interfaces() {
    // yields all "namespace.method" strings
  }

  return { invoke, interfaces }
}
```

Each platform defines a router mapping namespaces to module objects:

```typescript
// agent/src/fruity/router.ts
export default {
  checksec,    // binary security checks
  classdump,   // runtime class extraction
  cookies,     // HTTP cookie access
  crypto,      // crypto API interception control
  fs,          // filesystem operations
  info,        // app info (bundle, version, paths)
  keychain,    // keychain dumping
  // ...
}
```

Types flow end-to-end: `RemoteRPC<T>` converts synchronous module methods to async promises, matching the RPC boundary.

## Socket.IO Events

### Namespaces

| Namespace | Purpose |
|-----------|---------|
| `/devices` | Device list change notifications |
| `/session` | Individual instrumentation session |

### Server → Client Events

| Event | Payload | Description |
|-------|---------|-------------|
| `ready` | `(pid: number)` | Session initialized, agent loaded |
| `log` | `(level: string, text: string)` | Agent log output |
| `syslog` | `(text: string)` | System log entry |
| `hook` | `(msg: BaseHookMessage)` | Hook interception event |
| `crypto` | `(msg: BaseHookMessage, data?: ArrayBuffer)` | Crypto API call captured |
| `nsurl` | `(event: NSURLEvent)` | Network request event (iOS) |
| `jni` | `(event: JNIEvent)` | JNI call event (Android) |
| `flutter` | `(event: Record<string, unknown>)` | Flutter method channel event |
| `lifecycle` | `(event: string)` | App lifecycle change (active/inactive/foreground/background) |
| `detached` | `(reason: string)` | Session disconnected |
| `fatal` | `(detail: unknown)` | Fatal error |
| `change` | `()` | Device list changed (on `/devices` namespace) |
| `invalid` | `()` | Invalid session parameters |

### Client → Server Events

| Event | Payload | Description |
|-------|---------|-------------|
| `rpc` | `(namespace, method, args, ack)` | Invoke agent RPC method |
| `eval` | `(source, name, ack)` | Evaluate JavaScript in agent |
| `clearLog` | `(type: "syslog" \| "agent", ack)` | Clear log file |

### Connection Parameters

The `/session` namespace expects these query params on connect:

| Param | Values | Description |
|-------|--------|-------------|
| `device` | device ID | Target Frida device |
| `platform` | `fruity` \| `droid` | iOS or Android |
| `mode` | `app` \| `daemon` | Attach to app or daemon process |
| `bundle` | bundle ID | App identifier (for `app` mode) |
| `pid` | number | Process ID (for `daemon` mode) |
| `name` | string | Display name |

## REST API Endpoints

All endpoints are prefixed with `/api`.

### Device Management

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/version` | Get Frida and igf versions |
| `GET` | `/d.ts/pack` | Get agent TypeScript type definitions |
| `GET` | `/devices` | List connected devices |
| `GET` | `/device/:device/apps` | List apps on device |
| `GET` | `/device/:device/processes` | List processes on device |
| `GET` | `/device/:device/icon/:bundle` | Get app icon (PNG) |
| `GET` | `/device/:device/info` | Get device system parameters |
| `POST` | `/device/:device/kill/:pid` | Kill a process |
| `PUT` | `/devices/remote/:hostname` | Add remote Frida device |
| `DELETE` | `/devices/remote/:hostname` | Remove remote Frida device |

### File Transfer

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/download/:device/:pid?path=...` | Download file from device |
| `POST` | `/upload/:device/:pid` | Upload file to device |

### Data & History

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/logs/:device/:identifier/:type` | Stream log file (syslog/agent) |
| `DELETE` | `/logs/:device/:identifier` | Delete all logs |
| `GET` | `/hooks/:device/:identifier` | Query hook logs (paginated) |
| `DELETE` | `/hooks/:device/:identifier` | Clear hook logs |
| `GET` | `/history/crypto/:device/:identifier` | Query crypto logs |
| `DELETE` | `/history/crypto/:device/:identifier` | Clear crypto logs |
| `GET` | `/history/jni/:device/:identifier` | Query JNI traces |
| `DELETE` | `/history/jni/:device/:identifier` | Clear JNI traces |
| `GET` | `/history/flutter/:device/:identifier` | Query Flutter logs |
| `DELETE` | `/history/flutter/:device/:identifier` | Clear Flutter logs |
| `GET` | `/history/nsurl/:device/:identifier` | Query network request logs |
| `DELETE` | `/history/nsurl/:device/:identifier` | Clear network request logs |
| `GET` | `/history/nsurl/:device/:identifier/attachment/:requestId` | Download request body |
| `GET` | `/pins/:device/:identifier` | Load pin snapshot |
| `DELETE` | `/pins/:device/:identifier` | Clear pin snapshot |

Query parameters for history endpoints: `limit`, `offset`, `since`, `category` (hooks), `method` (JNI).

### LLM

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/llm` | LLM integration endpoint |

## End-to-End Data Flow

### Example: Hooking an Objective-C Method

1. **User** clicks "Add Hook" in the Hooks panel, selects `-[NSURLSession dataTaskWithRequest:]`

2. **Frontend** emits Socket.IO RPC:
   ```javascript
   socket.emit("rpc", "pins", "add", [{ category: "objc", symbol: "..." }], callback)
   ```

3. **Server** (`ws.ts`) receives the `rpc` event and calls:
   ```javascript
   script.exports.invoke("pins", "add", [{ category: "objc", symbol: "..." }])
   ```

4. **Agent** (`common/pins.ts`) installs the Interceptor hook in the target process

5. **Agent** sends hook events back via `send()` when the hooked method is called

6. **Server** receives script messages, persists to `HookStore` (SQLite), and emits:
   ```javascript
   socket.emit("hook", { symbol, direction, timestamp, ... })
   ```

7. **Frontend** receives the `hook` event, updates TanStack Query cache, and renders the log entry

8. **Server** auto-saves the pin snapshot after changes via `script.exports.snapshot()`, persisted to disk for session recovery

### Example: Browsing the Filesystem

1. **Frontend** calls `rpc.fs.ls("/var/mobile")` via the proxy
2. Proxy emits `socket.emit("rpc", "fs", "ls", ["/var/mobile"], callback)`
3. Server calls `script.exports.invoke("fs", "ls", ["/var/mobile"])`
4. Agent's `fs` module calls Frida's `ObjC.classes.NSFileManager` APIs
5. Result propagates back through `ack` callback to the frontend promise

## Type Sharing Across Layers

Types flow from agent to frontend:

1. Agent modules define method signatures in TypeScript
2. `tsgo` generates type definitions to `agent/types/`
3. Vite aliases `@agent` to `../agent/types` so the GUI can import them
4. `RemoteRPC<T>` type helper wraps all methods as async (reflecting the RPC boundary)
5. `createProxy()` returns a typed proxy matching the agent interface

This ensures that calling `rpc.fs.ls("/")` in the frontend is fully type-checked against the agent's actual `fs.ls` implementation.

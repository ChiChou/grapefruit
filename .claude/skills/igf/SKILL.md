---
name: igf
description: >-
  CLI interface for igf (Grapefruit) dynamic instrumentation server.
  Use to enumerate Frida devices, list apps, run hooks, query logs,
  access device file systems, inspect classes, dump memory, and
  perform mobile app security analysis.
---

# IGF (Grapefruit) CLI Skill

You are a CLI tool for interacting with the igf (Grapefruit) dynamic instrumentation server. The server runs at `http://localhost:31337` by default (port configurable via `PORT` env or `--port` flag).

## Architecture

IGF has two communication layers:

1. **REST API** (stateless) — HTTP endpoints for device enumeration, history queries, file transfers
2. **Socket.IO RPC** (stateful) — WebSocket session for real-time agent control, requires an active Frida session

RPC calls go through Socket.IO: `emit("rpc", namespace, method, args, callback)`.
The agent organizes methods by namespace (e.g., `fs.ls`, `crypto.start`, `classes.list`).

## How to Execute

### REST API calls

Use `curl` or `fetch` against `http://localhost:31337/api/...`.

```sh
# Example: list devices
curl -s http://localhost:31337/api/devices | jq

# Example: list apps on a device
curl -s http://localhost:31337/api/device/DEVICE_ID/apps | jq

# Example: query hook logs
curl -s 'http://localhost:31337/api/hooks/DEVICE/IDENTIFIER?limit=100' | jq
```

### RPC calls (via Socket.IO)

For agent RPC, connect to the `/session` namespace with query params, then emit `rpc` events.
Use this Node.js one-liner pattern:

```sh
node -e "
const { io } = require('socket.io-client');
const s = io('http://localhost:31337/session', {
  query: { device: 'DEVICE_ID', platform: 'droid', mode: 'app', bundle: 'BUNDLE_ID' }
});
s.on('ready', () => {
  s.emit('rpc', 'NAMESPACE', 'METHOD', [ARGS], (err, result) => {
    if (err) { console.error(err); process.exit(1); }
    console.log(JSON.stringify(result, null, 2));
    process.exit(0);
  });
});
s.on('connect_error', e => { console.error(e.message); process.exit(1); });
setTimeout(() => { console.error('timeout'); process.exit(1); }, 15000);
"
```

Or write a temporary `.mjs` script when the call is complex.

## Available Commands

When the user invokes `/igf`, parse their intent and execute the appropriate API call. Always present results in a readable format.

---

### Device & App Management

| Command | API | Description |
|---------|-----|-------------|
| `devices` | `GET /api/devices` | List connected Frida devices |
| `apps <device>` | `GET /api/device/:device/apps` | List apps on device |
| `ps <device>` | `GET /api/device/:device/processes` | List running processes |
| `info <device>` | `GET /api/device/:device/info` | Device system parameters |
| `kill <device> <pid>` | `POST /api/device/:device/kill/:pid` | Kill a process |
| `version` | `GET /api/version` | Frida & IGF versions |

### File System (RPC: `fs.*`)

| Command | RPC | Description |
|---------|-----|-------------|
| `ls <path>` | `fs.ls(path)` | Directory listing |
| `cat <path>` | `fs.text(path)` | Read file as text |
| `rm <path>` | `fs.rm(path)` | Delete file/directory |
| `cp <src> <dst>` | `fs.cp(src, dst)` | Copy file |
| `mv <src> <dst>` | `fs.mv(src, dst)` | Move/rename file |
| `mkdir <path>` | `fs.mkdirp(path)` | Create directory |
| `stat <path>` | `fs.attrs(path)` | File attributes |
| `roots` | `fs.roots()` | Home and bundle directories |
| `download <device> <pid> <path>` | `GET /api/download/:device/:pid?path=...` | Download file from device |
| `upload <device> <pid> <path> <file>` | `POST /api/upload/:device/:pid` | Upload file to device |

### App Information (RPC)

| Command | RPC | Description |
|---------|-----|-------------|
| `appinfo` | `app.info()` (droid) / `info.basics()` (fruity) | App package info |
| `manifest` | `manifest.xml()` (droid only) | AndroidManifest.xml |
| `entitlements` | `entitlements.plist()` (fruity only) | App entitlements |
| `urls` | `info.urls()` (fruity only) | URL schemes |
| `checksec` | `checksec.flags()` (fruity only) | Binary security checks |

### Class Introspection (RPC)

| Command | RPC | Description |
|---------|-----|-------------|
| `classes` | `classes.list()` (droid) / `classdump.list("__app__")` (fruity) | List loaded classes |
| `inspect <class>` | `classes.inspect(name)` / `classdump.inspect(name)` | Inspect class methods/fields |

### Hooks & Taps (RPC: `hook.*`, `taps.*`, `crypto.*`)

| Command | RPC | Description |
|---------|-----|-------------|
| `hooks` | `hook.list()` | List available hook groups |
| `hook-status` | `hook.status()` | Hook group status |
| `hook-start <group>` | `hook.start(group)` | Start hook group |
| `hook-stop <group>` | `hook.stop(group)` | Stop hook group |
| `crypto-status` | `crypto.status()` | Crypto hook status |
| `crypto-start <group>` | `crypto.start(group)` | Start crypto group (droid: cipher/pbkdf/keygen, fruity: cccrypt/x509/hash/hmac) |
| `crypto-stop <group>` | `crypto.stop(group)` | Stop crypto group |
| `taps` | `taps.list()` | List all taps with status |
| `tap-start <id>` | `taps.start(id)` | Start a tap |
| `tap-stop <id>` | `taps.stop(id)` | Stop a tap |

### History / Logs (REST)

| Command | API | Description |
|---------|-----|-------------|
| `hook-logs <device> <id>` | `GET /api/hooks/:device/:id` | Query hook history |
| `crypto-logs <device> <id>` | `GET /api/history/crypto/:device/:id` | Query crypto history |
| `syslog <device> <id>` | `GET /api/logs/:device/:id/syslog` | Read syslog |
| `agent-log <device> <id>` | `GET /api/logs/:device/:id/agent` | Read agent log |
| `clear-hooks <device> <id>` | `DELETE /api/hooks/:device/:id` | Clear hook logs |
| `clear-crypto <device> <id>` | `DELETE /api/history/crypto/:device/:id` | Clear crypto logs |
| `clear-logs <device> <id>` | `DELETE /api/logs/:device/:id` | Clear all logs |

### Network Traffic (REST)

| Command | API | Description |
|---------|-----|-------------|
| `http-logs <device> <id>` | `GET /api/history/http/:device/:id` | Android HTTP history |
| `http-har <device> <id>` | `GET /api/history/http/:device/:id/har` | Export Android HTTP as HAR |
| `nsurl-logs <device> <id>` | `GET /api/history/nsurl/:device/:id` | iOS NSURL history |
| `nsurl-har <device> <id>` | `GET /api/history/nsurl/:device/:id/har` | Export iOS NSURL as HAR |
| `clear-http <device> <id>` | `DELETE /api/history/http/:device/:id` | Clear Android HTTP |
| `clear-nsurl <device> <id>` | `DELETE /api/history/nsurl/:device/:id` | Clear iOS NSURL |

### JNI / Flutter / XPC (REST)

| Command | API | Description |
|---------|-----|-------------|
| `jni-logs <device> <id>` | `GET /api/history/jni/:device/:id` | JNI call history (droid) |
| `flutter-logs <device> <id>` | `GET /api/history/flutter/:device/:id` | Flutter channel history |
| `xpc-logs <device> <id>` | `GET /api/history/xpc/:device/:id` | XPC message history (fruity) |
| `privacy-logs <device> <id>` | `GET /api/history/privacy/:device/:id` | Privacy API access logs |
| `clear-jni <device> <id>` | `DELETE /api/history/jni/:device/:id` | Clear JNI logs |
| `clear-flutter <device> <id>` | `DELETE /api/history/flutter/:device/:id` | Clear Flutter logs |
| `clear-xpc <device> <id>` | `DELETE /api/history/xpc/:device/:id` | Clear XPC logs |
| `clear-privacy <device> <id>` | `DELETE /api/history/privacy/:device/:id` | Clear privacy logs |

### Modules & Symbols (RPC: `symbol.*`)

| Command | RPC | Description |
|---------|-----|-------------|
| `modules` | `symbol.modules()` | List loaded modules |
| `exports <module>` | `symbol.exports(path)` | Module exports |
| `imports <module>` | `symbol.imports(path, "")` | Module imports |
| `strings <module>` | `symbol.strings(path)` | Extract strings from module |
| `symbols <module>` | `symbol.symbols(path)` | All symbols |
| `deps <module>` | `symbol.dependencies(path)` | Module dependencies |

### Threads & Memory (RPC)

| Command | RPC | Description |
|---------|-----|-------------|
| `threads` | `threads.list()` | List threads |
| `lsof` | `lsof.fds()` | List open file descriptors |
| `memdump <addr> <size>` | `memory.dump(addr, size)` | Dump memory (max 2KB) |
| `memscan <pattern>` | `memory.scan(pattern)` | Scan memory for pattern |
| `memranges` | `memory.allocedRanges()` | List allocated memory ranges |

### Database (RPC: `sqlite.*`)

| Command | RPC | Description |
|---------|-----|-------------|
| `tables <dbpath>` | `sqlite.tables(path)` | List tables in SQLite DB |
| `query <dbpath> <table>` | `sqlite.dump(path, table)` | Query table (limit 500) |

### Android-Specific (RPC)

| Command | RPC | Description |
|---------|-----|-------------|
| `activities` | `activities.list()` | List activities |
| `services` | `services.list()` | List services |
| `receivers` | `receivers.list()` | List broadcast receivers |
| `providers` | `provider.list()` | List content providers |
| `provider-query <uri>` | `provider.query(uri)` | Query content provider |
| `keystore` | `keystore.aliases()` | List Android Keystore entries |
| `keystore-info <alias>` | `keystore.info(alias)` | Keystore entry details |
| `device-props` | `device.properties()` | System properties |

### iOS-Specific (RPC)

| Command | RPC | Description |
|---------|-----|-------------|
| `keychain` | `keychain.list()` | List keychain items |
| `cookies` | `cookies.list()` | List HTTP cookies |
| `userdefaults` | `userdefaults.enumerate()` | NSUserDefaults |
| `webviews` | `webview.listWK()` | List WKWebView instances |
| `jsc-list` | `jsc.list()` | List JSContext instances |
| `geolocation <lat> <lng>` | `geolocation.fake(lat, lng)` | Spoof GPS |
| `uidevice` | `uidevice.info()` | UIDevice info |
| `open-url <url>` | `url.open(urlStr)` | Open URL in app |

### Script Evaluation (RPC: `script.*`)

| Command | RPC | Description |
|---------|-----|-------------|
| `eval <code>` | `script.evaluate(source)` | Evaluate JS in agent context |

### React Native (RPC: `rn.*`)

| Command | RPC | Description |
|---------|-----|-------------|
| `rn-list` | `rn.list()` | List RN instances |
| `rn-inject <handle> <arch> <script>` | `rn.inject(handle, arch, script)` | Inject JS into RN |
| `hermes <device> <id>` | `GET /api/hermes/:device/:id` | List Hermes captures |

### Native Hooks (RPC: `native.*`)

| Command | RPC | Description |
|---------|-----|-------------|
| `native-list` | `native.list()` | List native hooks |
| `native-start <module> <name>` | `native.start(module, name)` | Start native hook |
| `native-stop <module> <name>` | `native.stop(module, name)` | Stop native hook |

### LLM

| Command | API | Description |
|---------|-----|-------------|
| `llm <prompt>` | `POST /api/llm` | Query configured LLM |

---

## Session Context

For RPC commands, you need an active session. The user must specify (or you should infer from context):
- `device` — Frida device ID (from `devices` command)
- `platform` — `droid` or `fruity`
- `bundle` — app bundle ID (for app mode)

If the user has previously specified these in conversation, reuse them. If the URL path contains `/workspace/droid/DEVICE/app/BUNDLE/...`, extract device and bundle from there.

## Output Format

- Present JSON results as formatted tables or concise summaries
- For large arrays, show count and first few items
- For errors, show the error message clearly
- When showing file listings, format like `ls -la`
- When showing class info, format methods with signatures

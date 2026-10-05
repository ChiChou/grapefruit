---
name: igf
description: >-
  Use Grapefruit's CLI for platform-specific mobile app inspection and
  managed captures. Query persisted evidence through the REST API.
  Use Frida directly for custom scripts and generic runtime primitives.
---

# IGF CLI

## Scope

Use IGF for platform-specific inspection (storage, keychain/keystore, manifests,
frameworks) and managed captures with persisted evidence and hook snapshots.
Use Frida's Python API or CLI for custom scripts, memory operations, threads,
module/symbol enumeration, and basic process metadata. Attach a separate Frida
session for that work.

The CLI and its daemon do not expose `script.*`, `memory.*`, `threads.*`,
`symbol.*` (except platform-specific `symbol.strings`), `info.processInfo`,
`webview.evaluate`, `jsc.run`, or `rn.inject`.

## Commands

```sh
igf rpc [target options] <namespace.method> [args...]
igf session ls --json
igf session open [target options]
igf session close <id>
igf session gc
igf daemon stop
igf setup [--global]
```

Target options:

- `--device <id> --platform <ios|android> --bundle <id>` for an app.
- `--device <id> --platform <ios|android> --pid <pid> [--name <name>]` for a process.
- `--session <id>` to reuse an explicit daemon session.

Reuse the target supplied by the user. `-L <label>` selects an isolated daemon;
`--project <path>` selects its data directory. `--replace` replaces an active iOS
app session when needed. `--json` requests predictable machine output.

RPC arguments are positional JSON values or plain strings. Use the actual
namespace and method names from `agent/src/{fruity,droid}/router.ts` and their
exported modules; there are no `igf agent`, `igf device`, `igf log`, or
`igf history` subcommands.

## Examples

```sh
# Inspect app storage
igf rpc --device DEVICE --platform android --bundle com.example.app fs.roots
igf rpc --session SESSION fs.ls /data/user/0/com.example.app
igf rpc --session SESSION sqlite.tables /path/to/database
igf rpc --session SESSION sqlite.dump /path/to/database users

# Inspect app metadata
igf rpc --device DEVICE --platform android --bundle com.example.app app.info
igf rpc --device DEVICE --platform ios --bundle com.example.app info.plist

# Manage captures
igf rpc --session SESSION pins.list
igf rpc --session SESSION pins.start crypto
igf rpc --session SESSION pins.snapshot
igf rpc --session SESSION pins.stop crypto
```

Common pin IDs:

- Both: `crypto`, `flutter`, `privacy`.
- Android: `http`, `jni`, `classloader`, `clipboard`, `broadcast`, `intent`,
  `sharedpref`, `pendingintent`, `sslpinning`, `webview`.
- iOS: `nsurl`, `xpc`, `sqlite`, `pasteboard`, `deviceid`, `biometric`, `fileops`.

RPC acquires a short lease and releases it after the call. The daemon keeps the
instrumentation session alive until idle collection closes it. Stop captures
when finished and retrieve their persisted results.

## Persisted Evidence and Device Discovery

The Web server is separate from the CLI daemon. Start `igf --no-open` with the
same `--project` directory to query its REST API (default localhost:31337).

```sh
curl -s http://localhost:31337/api/devices
curl -s http://localhost:31337/api/device/DEVICE/apps
curl -s 'http://localhost:31337/api/history/crypto/DEVICE/com.example.app?limit=50'
curl -s 'http://localhost:31337/api/history/http/DEVICE/com.example.app?limit=50'
curl -s 'http://localhost:31337/api/history/nsurl/DEVICE/com.example.app?limit=50'
```

Additional history types include `jni`, `flutter`, `xpc`, `privacy`, and
`hermes`. Hook records are at `/api/hooks/DEVICE/IDENTIFIER`. Consult `src/routes/data.ts` and `src/routes/hermes.ts` for filters
and attachments. Present findings with actual captured evidence. Summarize large
results and retrieve only the records needed.

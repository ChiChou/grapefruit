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
The agent organizes methods by namespace (e.g., `fs.ls`, `pins.start`, `classes.list`).

## How to Execute

Use the `igf` CLI directly. All commands follow the pattern:

```
igf <command> [subcommand] [args] [options]
```

### Global Options

- `-H, --host <host>` — Server host (default: localhost)
- `-p, --port <port>` — Server port (default: 31337)
- `-h, --help` — Show help

### Session Options (for `agent` commands)

- `-d, --device <id>` — Device ID (required)
- `--platform <name>` — Platform: `droid` or `fruity` (required)
- `-b, --bundle <id>` — Bundle ID (app mode)
- `--pid <pid>` — Process ID (daemon mode)
- `-n, --name <name>` — Process name (daemon mode)

---

## Commands

### Device & App Management

| Command | Description |
|---------|-------------|
| `igf device list` | List connected Frida devices |
| `igf device apps <device>` | List apps on device |
| `igf device ps <device>` | List running processes |
| `igf device info <device>` | Device system parameters |
| `igf device kill <device> <pid>` | Kill a process |
| `igf version` | Frida & IGF versions |

### Log Management

| Command | Description |
|---------|-------------|
| `igf log hooks <device> <id> [--limit N]` | Query hook logs |
| `igf log crypto <device> <id> [--limit N]` | Query crypto logs |
| `igf log syslog <device> <id>` | Read syslog |
| `igf log agent <device> <id>` | Read agent log |
| `igf log clear <device> <id>` | Clear all logs |

### History

| Command | Description |
|---------|-------------|
| `igf history http <device> <id>` | Android HTTP history |
| `igf history nsurl <device> <id>` | iOS NSURL history |
| `igf history jni <device> <id>` | JNI call history (droid) |
| `igf history flutter <device> <id>` | Flutter channel history |
| `igf history xpc <device> <id>` | XPC message history (fruity) |
| `igf history privacy <device> <id>` | Privacy API access logs |
| `igf history hermes <device> <id>` | Hermes JS captures |

### Agent Commands (requires session)

All `agent` commands require session options: `-d <device> --platform <droid|fruity> -b <bundle>` (app mode) or `-d <device> --platform <droid|fruity> --pid <pid>` (daemon mode).

#### File System (`fs`)

```
igf agent fs ls <path> [session opts]
igf agent fs cat <path> [session opts]
igf agent fs rm <path> [session opts]
igf agent fs cp <src> <dst> [session opts]
igf agent fs mv <src> <dst> [session opts]
igf agent fs mkdir <path> [session opts]
igf agent fs stat <path> [session opts]
igf agent fs roots [session opts]
```

#### App Information (`app`)

```
igf agent app info [session opts]
igf agent app manifest [session opts]        # Android only
igf agent app entitlements [session opts]    # iOS only
igf agent app urls [session opts]            # iOS only
```

#### Binary Security (`checksec`)

```
igf agent checksec all [session opts]
igf agent checksec main [session opts]
```

#### Class Introspection (`class`)

```
igf agent class list [session opts]
igf agent class inspect <name> [session opts]
```

#### Hook Management (`hook`)

```
igf agent hook list [session opts]
igf agent hook status [session opts]
igf agent hook start <group> [session opts]
igf agent hook stop <group> [session opts]
```

#### Crypto Hooks (`crypto`)

```
igf agent crypto status [session opts]
igf agent crypto start <group> [session opts]   # droid: cipher/pbkdf/keygen, fruity: cccrypt/x509/hash/hmac
igf agent crypto stop <group> [session opts]
```

#### Pin Management (`pin`)

```
igf agent pin list [session opts]
igf agent pin start <id> [session opts]
igf agent pin stop <id> [session opts]
```

#### Module & Symbols (`symbol`)

```
igf agent symbol modules [session opts]
igf agent symbol exports <module> [session opts]
igf agent symbol imports <module> [session opts]
igf agent symbol strings <module> [session opts]
igf agent symbol symbols <module> [session opts]
igf agent symbol deps <module> [session opts]
```

#### Threads & Memory

```
igf agent thread list [session opts]
igf agent memory dump <addr> <size> [session opts]
igf agent memory scan <pattern> [session opts]
igf agent memory ranges [session opts]
igf agent lsof [session opts]
```

#### SQLite Database (`sqlite`)

```
igf agent sqlite tables <path> [session opts]
igf agent sqlite dump <path> <table> [session opts]
```

#### Android-Specific (`android`)

```
igf agent android activities [session opts]
igf agent android services [session opts]
igf agent android receivers [session opts]
igf agent android providers [session opts]
igf agent android provider-query <uri> [session opts]
igf agent android keystore [session opts]
igf agent android keystore-info <alias> [session opts]
igf agent android device-props [session opts]
```

#### iOS-Specific (`ios`)

```
igf agent ios keychain [session opts]
igf agent ios cookies [session opts]
igf agent ios userdefaults [session opts]
igf agent ios webviews [session opts]
igf agent ios jsc [session opts]
igf agent ios geolocation <lat> <lng> [session opts]
igf agent ios uidevice [session opts]
igf agent ios open-url <url> [session opts]
```

#### Script Evaluation

```
igf agent eval '<code>' [session opts]
```

#### React Native (`rn`)

```
igf agent rn list [session opts]
igf agent rn inject <handle> <arch> <script> [session opts]
```

#### Native Hooks (`native`)

```
igf agent native list [session opts]
igf agent native start <module> <name> [session opts]
igf agent native stop <module> <name> [session opts]
```

---

## Examples

```sh
# List devices
igf device list

# List apps on a device
igf device apps 5c1234

# List directory on Android app
igf agent fs ls / -d 5c1234 --platform droid -b com.example.app

# Start SSL pinning bypass hook
igf agent hook start ssl -d 5c1234 --platform droid -b com.example.app

# Inspect a class
igf agent class inspect com.example.MyClass -d 5c1234 --platform droid -b com.example.app

# Query hook logs
igf log hooks 5c1234 com.example.app --limit 50
```

## Session Context

For `agent` commands, you need an active session. The user must specify (or you should infer from context):
- `device` — Frida device ID (from `igf device list`)
- `platform` — `droid` or `fruity`
- `bundle` — app bundle ID (for app mode)

If the user has previously specified these in conversation, reuse them.

## Output Format

- Present JSON results as formatted tables or concise summaries
- For large arrays, show count and first few items
- For errors, show the error message clearly
- When showing file listings, format like `ls -la`
- When showing class info, format methods with signatures

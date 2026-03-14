<img src="gui/src/assets/logo.svg" alt="logo" width="320">

# Grapefruit: Runtime Application Exploration

[![John Discord](https://discord.com/api/guilds/591601634266578944/embed.png)](https://discord.com/invite/pwutZNx)
[![npm version](https://img.shields.io/npm/v/igf?color=blue)](https://www.npmjs.com/package/igf)
[![Commits](https://img.shields.io/github/commit-activity/w/chichou/grapefruit?label=Commits)](https://github.com/ChiChou/Grapefruit/commits/master)
[![contributers](https://img.shields.io/github/contributors/chichou/grapefruit)](https://github.com/ChiChou/Grapefruit/graphs/contributors)
[![License](https://img.shields.io/github/license/chichou/grapefruit)](https://github.com/ChiChou/Grapefruit/blob/master/LICENSE)

> **Warning**: This project is under active development and is not ready for production use.

Runtime mobile application instrumentation toolkit powered by [Frida](https://frida.re).
Inspect, hook, and modify mobile apps through a web-based interface.

Now it supports both iOS and Android!

## Features

- **Runtime Method Hooking** - Intercept native and managed functions with structured logging
- **Cryptographic API Interception** - Monitor encryption/decryption operations with data capture
- **Filesystem Browser** - Navigate, upload, download, and inspect files with hex/text preview
- **SQLite Database Inspection** - Browse tables, run queries, and view results
- **Syslog Streaming** - Real-time system and agent log monitoring
- **Process Crash Reporting** - Exception handler with register dump and backtrace
- **Flutter Support** - Monitor platform method channel communication on both platforms
- **React Native Support** - Bridge inspector and JavaScript injection REPL
- **Memory Scanner** - Search and inspect process memory
- **Privacy Monitor** - Track sensitive API access (camera, microphone, location, sensors, etc.)
- **Thread Inspector** - View and manage process threads
- **Module/Symbol Browser** - Inspect loaded modules and exported symbols

### iOS

- Keychain access and modification
- NSURL session traffic capture (HTTP/HTTPS/WebSocket)
- WebView and JSContext inspection with JavaScript execution
- UI hierarchy dump and element highlighting
- Info.plist, entitlements, and binary cookie viewers
- Biometric (Touch ID / Face ID) bypass
- UserDefaults browser
- Pasteboard and file operation monitoring
- Geolocation spoofing
- Device ID spoofing
- Objective-C class and method inspection
- Open file handles and network connections (lsof)
- Security analysis (PIE, ARC, stack canaries, encryption)
- Asset catalog viewer (Assets.car)
- XPC/NSXPC message inspection
- Firebase/Firestore monitoring

### Android

- AndroidManifest.xml decoder and component browser (activities, services, receivers, providers)
- Android Keystore inspection with key attributes
- Content provider query, insert, update, and delete
- JNI call tracing with arguments, return values, and backtraces
- Java class inspection (methods, fields, interfaces)
- Intent building and launching
- Open file handles and network connections (lsof)
- HTTP traffic capture (OkHttp, Volley, URLConnection)
- Resources browser
- Clipboard and SharedPreferences monitoring
- Broadcast receiver monitoring

## Documentation

- [Development](docs/dev.md)
- [Architecture](docs/arch.md)
- [RPC](docs/rpc.md)

## License

[MIT](LICENSE)

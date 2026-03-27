# Grapefruit Documentation

Grapefruit is a runtime mobile security research toolkit for iOS and Android. It provides a browser-based interface for dynamic instrumentation, binary analysis, and data inspection.

This project is a successor to [Passionfruit](https://github.com/chaitin/passionfruit), rewritten from scratch with a modern stack and significantly expanded scope.

## Quick Start

```
npx igf
```

Then visit the URL shown in your terminal. For prebuilt binaries and other options, see the [installation guide](/docs/install).

## Feature Guide

- [Installation](/docs/install) — npm, prebuilt binaries, platform-specific setup
- [Known Limitations](/docs/limits) — what this tool does not do
- [Analysis & Decompilation](/docs/analysis) — native disassembly, DEX class browser, Hermes decompiler, AI decompilation, control flow graphs
- [Instrumentation](/docs/instrumentation) — function hooking, class/method browsing, module listing, thread inspection
- [File Browser & Previews](/docs/files) — filesystem navigation, hex view, SQLite editor, plist viewer, image/audio/font preview
- [Data Inspection](/docs/data) — keychain/keystore, network monitoring, crypto interception, privacy auditing
- [Platform Features](/docs/platforms) — iOS (entitlements, Info.plist, XPC, JSContext) and Android (APK browser, content providers, JNI trace, resources)
- [LLM Configuration](/docs/llm) — set up AI decompilation with Anthropic, OpenAI, Gemini, or OpenRouter

## Architecture

Grapefruit runs as a local server with three components:

- **Server** — Node.js/Bun process that manages Frida sessions and serves the web UI
- **Agent** — Frida agent injected into the target app for runtime instrumentation
- **GUI** — React frontend with dockable panels, code editor, and terminal views

## Requirements

- Node.js 22+ or Bun 1.1+
- A jailbroken iOS device or rooted Android device
- Frida server running on the target device
- Optional: LLM API key for AI decompilation — see [LLM Configuration](/docs/llm)

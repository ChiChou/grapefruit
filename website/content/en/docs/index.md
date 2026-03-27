# Grapefruit Documentation

Grapefruit is a runtime mobile security research toolkit for iOS and Android. It provides a browser-based interface for dynamic instrumentation, binary analysis, and data inspection.

## Quick Start

```
npx igf
```

Then visit the URL shown in your terminal. For prebuilt binaries and other options, see the [installation guide](/docs/install).

## Why Grapefruit?

Grapefruit started as a fork of [Passionfruit](https://github.com/chaitin/passionfruit), but development stalled due to limited bandwidth. The rise of large language models changed the equation — AI assistance dramatically accelerates development, making it possible to iterate and expand in ways that weren't feasible before.

Most mobile security tools demand lengthy, intricate commands for each task. Grapefruit rethinks this with a point-and-click interface that handles the command complexity behind the scenes. Beyond the GUI, it offers **agent SKILLS** that expose capabilities to both humans and AI in a structured, composable way.

Grapefruit does not include built-in RASP bypasses — see [Known Limitations](/docs/limits) for the rationale.

## Claude Code Integration

Grapefruit ships with **agent SKILLS** that expose all CLI capabilities to Claude Code:

```sh
igf setup           # install to .claude/skills/ in current project
igf setup --global  # install to ~/.claude/skills/ (available in all projects)
```

After installation, use `/igf` in Claude Code to interact with the IGF server, or `/audit` for autonomous mobile security audits aligned with OWASP MASTG.

## Feature Guide

- [Installation](/docs/install) — npm, prebuilt binaries, platform-specific setup
- [Analysis & Decompilation](/docs/analysis) — native disassembly, DEX class browser, Hermes decompiler, AI decompilation, control flow graphs
- [Instrumentation](/docs/instrumentation) — function hooking, class/method browsing, module listing, thread inspection
- [File Browser & Previews](/docs/files) — filesystem navigation, hex view, SQLite editor, plist viewer, image/audio/font preview
- [Data Inspection](/docs/data) — keychain/keystore, network monitoring, crypto interception, privacy auditing
- [Platform Features](/docs/platforms) — iOS (entitlements, Info.plist, XPC, JSContext, WKWebView) and Android (APK browser, content providers, JNI trace, resources, WebView)
- [LLM Configuration](/docs/llm) — set up AI decompilation with Anthropic, OpenAI, Gemini, or OpenRouter

## Architecture

Grapefruit runs as a local server with three components:

- **Server** — Node.js/Bun process that manages Frida sessions and serves the web UI
- **Agent** — Frida agent injected into the target app for runtime instrumentation
- **GUI** — React frontend with dockable panels, code editor, and terminal views

## Requirements

- Node.js 22+ or Bun 1.3.6+
- A jailbroken iOS device or rooted Android device
- Frida server running on the target device
- Optional: LLM API key for AI decompilation — see [LLM Configuration](/docs/llm)

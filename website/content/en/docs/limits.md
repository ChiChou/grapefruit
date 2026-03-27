# Known Limitations

## No Anti-Tampering Bypass

Grapefruit does not include built-in bypasses for:

- Frida detection
- SSL/TLS certificate pinning
- Jailbreak or root detection

RASP (Runtime Application Self-Protection) solutions evolve continuously to detect instrumentation frameworks. Maintaining effective bypasses requires ongoing effort to keep pace with new detection methods, introducing significant maintenance burden and stability issues. These bypasses are also highly app-specific, making general-purpose solutions fragile.

Rather than shipping brittle built-in bypasses, Grapefruit focuses on instrumentation and inspection capabilities that compose well with dedicated bypass tooling.

### Recommended Approaches

- **Frida Syscall Tracer** — Use `frida-strace` (Frida 17.8.0+) to trace system calls and find detection artifacts before attaching Grapefruit.
- **Multi-session Architecture** — Spawn a separate Frida session with your RASP bypass scripts first, then launch Grapefruit. It attaches to the existing process rather than respawning, preserving any bypasses already in effect.

## HTTP Monitoring Is Hook-Based

The HTTP/NSURL traffic capture on both iOS and Android works by hooking high-level networking APIs. This is fundamentally different from a MITM proxy and has several implications:

- **Incomplete coverage** — Traffic from custom network stacks, raw sockets, or non-standard HTTP clients will not be captured.
- **Not a proxy replacement** — For comprehensive traffic analysis, use a dedicated MITM proxy alongside Grapefruit.
- **gRPC and WebSocket** — These protocols often bypass the hooked HTTP layer and may not appear in the traffic log.

## Static Analysis Scope

- **No DEX decryption** — Apps protected by packers encrypt or hide the real DEX at rest. Grapefruit analyzes the on-disk file as-is and does not attempt runtime DEX dumping or decryption. For packed apps, use a dedicated unpacker first and feed the decrypted DEX manually.
- **DEX analysis requires the file** — The DEX viewer downloads and analyzes the file server-side with radare2. Very large DEX files (multi-dex APKs with 100k+ methods) may take several seconds for initial `aa` analysis.
- **No cross-DEX references** — Each DEX file is analyzed independently. References between multiple DEX files in a multi-dex app are not resolved.
- **Obfuscated code** — The class/method browser shows whatever names are in the binary. Obfuscated apps (ProGuard, R8, DexGuard) will show shortened names like `La/b/c;`. Grapefruit does not attempt deobfuscation.

## Disassembly and Decompilation

The built-in disassembler and decompiler are convenience features for quick triage, not replacements for dedicated reverse engineering tools.

For serious analysis, pull the binary from the device (using the file browser or APK browser) and open it in a dedicated tool. The in-app views are best used for quick lookups — checking what a function does before hooking it, or navigating from a string xref to surrounding code.

## AI Decompilation Quality

- **LLM-dependent** — Output quality varies significantly by model. Larger models generally produce better results.
- **Not verified** — The decompiled code is a best-effort reconstruction. It may contain errors, miss edge cases, or hallucinate logic that doesn't exist in the original.
- **Large functions** — Functions exceeding the model's context window will be truncated, producing incomplete output.
- **Token cost** — Each decompilation request sends the full function disassembly. Large functions with many basic blocks consume significant tokens.

## Platform Requirements

- **Jailbreak / root required** — Grapefruit requires Frida server running with elevated privileges on the target device. Non-jailbroken iOS and non-rooted Android are not supported.
- **USB connection** — The default setup requires a USB connection to the target device. Remote Frida connections are supported but require manual configuration.
- **Single device at a time** — Each Grapefruit session connects to one device. To work with multiple devices, run multiple server instances on different ports.

## Process Mode

When attaching to system processes in process mode, be aware of platform-specific constraints:

- **Sandbox restrictions** — System services run with reduced privileges under mobile sandboxing. Some services may refuse attachment entirely or crash when accessed outside their expected runtime context.
- **Memory pressure** — Low-memory services may be terminated if instrumentation overhead exceeds available headroom.
- **Limited feature set** — App-dependent features (Info.plist, Entitlements, WebViews, etc.) are unavailable; only generic features like checksec, file browser, handles, and memory scanner are functional.

## Stability

Grapefruit instruments a live process by injecting code at runtime. This is inherently invasive and can cause instability:

- **Hooking can crash the target app** — Replacing function implementations at runtime may trigger unexpected behavior, especially if the hook alters timing, thread safety, or return values in ways the app doesn't anticipate.
- **Tracing high-frequency functions** — Hooking frequently called functions adds overhead that can degrade performance or cause the app to become unresponsive.
- **Multi-threaded code** — Hooks on functions called from multiple threads concurrently may introduce race conditions that don't exist in the original app.
- **Process attachment** — Attaching to a process that is in the middle of initialization or has anti-debug checks may cause immediate termination.

These are fundamental trade-offs of dynamic instrumentation, not bugs in Grapefruit. When the target crashes, simply re-launch and try a more targeted approach.

## Browser Compatibility

- **Chromium-based browsers recommended** — The UI uses Monaco Editor, dockview, and xterm.js, which work best in Chromium-based browsers.
- **Mobile browsers** — The workspace is designed for desktop use. It renders on mobile but the dockable panel layout is not practical on small screens.

## Memory and Performance

- **Analysis sessions** — Each disassembly tab or DEX viewer creates a server-side analysis session. Concurrent sessions consume memory proportional to the number of open views.
- **Large binary analysis** — Analyzing large binaries with tens of thousands of functions can take significant time and memory.

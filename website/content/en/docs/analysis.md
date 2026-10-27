# Analysis & Decompilation

## Interactive Decompiler

![Split View with CFG](/radare2.webp)

Grapefruit includes a fully browser-based decompiler with radare2 for disassembly, Kuna for native source, DDC for Java, and r2hermes for Hermes bytecode, compiled to WebAssembly. Drop any binary file — ELF, Mach-O, DEX, or Hermes bytecode — and start reversing immediately. No device connection, no server-side processing, no setup.

The split view shows disassembly alongside a control flow graph. Switch between linear, graph, and offline decompiler modes. Browse functions, classes, strings, and cross-references in an integrated workspace.

## Live Disassembly

![Native Disassembly](/disasm.webp)

For live processes, memory is read on demand from the target device. Tap a function address in the module or class browser to open it in a disassembly tab with three views:

- **Linear** — Full function disassembly with syntax highlighting
- **Graph** — Control flow graph with basic blocks and jump/fail edges
- **Decompiler** — Kuna decompilation of the live function snapshot

The **Graph** view renders control flow with basic blocks and edges, color-coded by branch direction (green for true, red for false, gray for unconditional).

## DEX Analysis

![DEX Analysis](/dex.webp)

Open any `.dex` file from the APK browser or file system. Grapefruit fetches the file server-side and loads it into a radare2 session.

- **Class browser** — Lists all classes from `ic` output. Expand a class to see its methods and fields. Search by class name.
- **Method disassembly** — Click a method to view its Dalvik bytecode. radare2 handles all instruction decoding natively.
- **String search** — Browse all strings in the DEX file. Click a string to find cross-references (which methods use it).
- **Cross-references** — Click an xref to jump directly to the referencing method's disassembly.
- **Decompile** — DDC reconstructs Java for the selected method's class locally in a browser worker.

## Hermes Bytecode Analysis

![Hermes Bytecode](/hermes.webp)

React Native apps using the Hermes engine compile JavaScript to proprietary bytecode. Grapefruit intercepts Hermes bytecode blobs at runtime and provides:

- **Disassembly** — Raw Hermes bytecode listing with function headers showing name, parameter count, and size
- **Pseudocode** — Rule-based decompilation from r2hermes that reconstructs JavaScript-like syntax from bytecodes


## Offline engines

Kuna supports x86, x64, ARM, Thumb, ARM64, and ARM64e. Other architectures retain radare2 disassembly and graph views. DDC handles individual DEX files; Hermes keeps its dedicated r2hermes pseudocode view. No decompilation request uses an LLM or API key.

Live decompilation uses a bounded function memory snapshot (up to 1 MiB), so external data, literal pools, and callee type information may be unavailable. File-backed analysis gives Kuna the complete binary. Switching away or selecting another function cancels the previous worker; each request has a 60-second limit.

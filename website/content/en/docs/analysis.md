# Analysis & Decompilation

## Native Disassembly

The disassembly engine runs radare2 as a WebAssembly module (WASI) on the server. Tap a function address in the module or class browser to open it in a disassembly tab with four views:

- **Linear** — Full function disassembly with syntax highlighting
- **Graph** — Control flow graph with basic blocks and jump/fail edges
- **Decompiler** — radare2's built-in pseudo-C decompiler output
- **AI Decompile** — Sends the disassembly to an LLM for high-quality C/C++ reconstruction with streaming output

For live processes, memory is read on demand so you can start analyzing without waiting for a full dump.

## DEX Analysis

Open any `.dex` file from the APK browser or file system. Grapefruit fetches the file server-side and loads it into a radare2 session.

- **Class browser** — Lists all classes from `ic` output. Expand a class to see its methods and fields. Search by class name.
- **Method disassembly** — Click a method to view its Dalvik bytecode. radare2 handles all instruction decoding natively.
- **String search** — Browse all strings in the DEX file. Click a string to find cross-references (which methods use it).
- **Cross-references** — Click an xref to jump directly to the referencing method's disassembly.
- **AI Decompile** — Decompile Dalvik bytecode to Java using an LLM.

## Hermes Bytecode Analysis

React Native apps using the Hermes engine compile JavaScript to proprietary bytecode. Grapefruit intercepts Hermes bytecode blobs at runtime and provides:

- **Disassembly** — Raw Hermes bytecode listing with function headers showing name, parameter count, and size
- **Pseudocode** — Rule-based decompilation from r2hermes that reconstructs JavaScript-like syntax from bytecodes
- **AI Decompile** — Sends both pseudocode and disassembly to an LLM to reconstruct idiomatic JavaScript with proper variable names, React/RN patterns, and simplified control flow

## AI Decompilation

All three analysis modes (native, DEX, Hermes) support AI-powered decompilation. Configure the LLM provider with environment variables:

```
LLM_PROVIDER=anthropic   # or openai, gemini, openrouter
LLM_API_KEY=sk-...
LLM_MODEL=claude-sonnet-4-20250514
```

Before submission, disassembly is stripped of decorative formatting to reduce token usage and latency. Function names and parameter counts from the symbol table are included for better context.

## Control Flow Graphs

The graph view renders control flow with basic blocks and edges, color-coded by branch direction.

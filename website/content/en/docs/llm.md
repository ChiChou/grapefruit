# LLM Configuration

Grapefruit can use a large language model to decompile disassembly into readable source code. This is available in the **AI Decompile** tab across all analysis views — native ARM/x86, Dalvik bytecode, and Hermes bytecode.

## How It Works

When you open the AI Decompile tab, Grapefruit sends the function disassembly to your configured LLM provider. The prompt includes:

- Function name and signature (when available from the symbol table)
- Stripped disassembly — addresses, pipe characters, and boilerplate headers are removed to reduce token usage
- For Hermes: both the rule-based pseudocode and raw bytecode for the model to cross-reference

The response streams back in real time, so you see the decompiled code as it generates. Results are cached per function for the duration of the session.

## Supported Providers

- **Anthropic** — Claude models (recommended for code quality)
- **OpenAI** — GPT models
- **Google Gemini**
- **OpenRouter** — access multiple models through a single API

## Setup

Set these environment variables before starting Grapefruit:

```
export LLM_PROVIDER=anthropic
export LLM_API_KEY=sk-ant-...
export LLM_MODEL=claude-sonnet-4-20250514
```

### Per-Provider Examples

```
# Anthropic
LLM_PROVIDER=anthropic
LLM_API_KEY=sk-ant-...
LLM_MODEL=claude-sonnet-4-20250514

# OpenAI
LLM_PROVIDER=openai
LLM_API_KEY=sk-...
LLM_MODEL=gpt-4o

# Gemini
LLM_PROVIDER=gemini
LLM_API_KEY=AIza...
LLM_MODEL=gemini-2.5-flash

# OpenRouter
LLM_PROVIDER=openrouter
LLM_API_KEY=sk-or-...
LLM_MODEL=anthropic/claude-sonnet-4-20250514
```

## Output Languages

The AI decompiler produces different languages depending on the input:

- **Native code** (ARM, x86) — decompiles to C/C++
- **Dalvik bytecode** (DEX) — decompiles to Java
- **Hermes bytecode** (React Native) — decompiles to JavaScript, with React/RN patterns reconstructed

## Privacy

Disassembly is sent to your configured LLM provider over HTTPS. No data is sent to any third party unless you configure an LLM provider. The feature is entirely optional — Grapefruit works fully without it.

## Without LLM

If no LLM is configured, the AI Decompile tab shows a configuration prompt. All other features (disassembly, pseudocode, CFG, class browsing, hooking, etc.) work without any LLM.

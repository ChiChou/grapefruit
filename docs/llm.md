# LLM Configuration

igf integrates with LLM providers for features like the GUI assistant and the `/audit` skill. Configuration is via environment variables.

## Quick Start

```bash
# Anthropic
LLM_PROVIDER=anthropic LLM_API_KEY=sk-ant-... LLM_MODEL=claude-sonnet-4-20250514 igf

# OpenAI
LLM_PROVIDER=openai LLM_API_KEY=sk-... LLM_MODEL=gpt-4o igf

# Local (Ollama)
LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=llama3 igf
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `LLM_PROVIDER` | No* | Built-in provider name (see below) |
| `LLM_BASE_URL` | No* | Custom API base URL |
| `LLM_API_KEY` | No | API key (skipped if empty, for local endpoints) |
| `LLM_MODEL` | Yes | Model identifier |

*At least one of `LLM_PROVIDER` or `LLM_BASE_URL` must be set.

## Built-in Providers

| Provider | Endpoint | Format |
|----------|----------|--------|
| `anthropic` | `https://api.anthropic.com` | Anthropic Messages API |
| `openai` | `https://api.openai.com` | OpenAI Chat Completions |
| `gemini` | `https://generativelanguage.googleapis.com` | Google Gemini |
| `openrouter` | `https://openrouter.ai/api` | OpenAI-compatible |

When using a built-in provider, `LLM_BASE_URL` is optional — the known endpoint is used automatically.

## Custom / OpenAI-Compatible Endpoints

Any endpoint that implements the OpenAI Chat Completions format (`POST /v1/chat/completions`) works via `LLM_BASE_URL`:

```bash
# Ollama (local, no API key needed)
LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=llama3

# vLLM
LLM_BASE_URL=http://localhost:8000/v1 LLM_MODEL=meta-llama/Llama-3-70b

# Together AI
LLM_BASE_URL=https://api.together.xyz LLM_API_KEY=... LLM_MODEL=meta-llama/Llama-3-70b-chat-hf

# Groq
LLM_BASE_URL=https://api.groq.com/openai LLM_API_KEY=... LLM_MODEL=llama3-70b-8192

# Fireworks
LLM_BASE_URL=https://api.fireworks.ai/inference LLM_API_KEY=... LLM_MODEL=accounts/fireworks/models/llama-v3-70b

# LM Studio (local)
LLM_BASE_URL=http://localhost:1234/v1 LLM_MODEL=local-model

# Azure OpenAI
LLM_BASE_URL=https://your-resource.openai.azure.com/openai/deployments/your-deployment LLM_API_KEY=... LLM_MODEL=gpt-4o
```

## Format Resolution

The request/response format is determined automatically:

1. `LLM_PROVIDER=anthropic` → Anthropic Messages API format
2. `LLM_PROVIDER=gemini` → Google Gemini format
3. Everything else (including custom `LLM_BASE_URL`) → OpenAI Chat Completions format

## API Endpoint

The server exposes `POST /api/llm` which accepts a plain text body and returns the LLM response as plain text. This is used by the GUI for inline analysis features.

```bash
curl -X POST http://localhost:31337/api/llm \
  -H "Content-Type: text/plain" \
  -d "Explain what this class does: NSURLSession"
```

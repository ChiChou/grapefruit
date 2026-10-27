# LLM Configuration

LLM configuration currently supplies native hook signature suggestions. Decompilation runs offline with Kuna, DDC, and r2hermes and requires no API key.

```sh
LLM_PROVIDER=anthropic LLM_API_KEY=sk-ant-... LLM_MODEL=your-model igf
```

Supported providers: `anthropic`, `openai`, `gemini`, and `openrouter`. Use `LLM_BASE_URL` for a custom OpenAI-compatible endpoint. Without a configured provider, hook parameter and return types can still be entered manually.

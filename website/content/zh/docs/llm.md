# LLM 配置

LLM 目前仅用于原生 Hook 的参数及返回类型建议。反编译使用 Kuna、DDC 和 r2hermes 离线执行，无需 API Key。

```sh
LLM_PROVIDER=anthropic LLM_API_KEY=sk-ant-... LLM_MODEL=your-model igf
```

支持 `anthropic`、`openai`、`gemini` 和 `openrouter`，也可通过 `LLM_BASE_URL` 配置兼容 OpenAI 的端点。不配置时仍可手动选择 Hook 类型。

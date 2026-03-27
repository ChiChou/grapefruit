# LLM 配置

Grapefruit 可以使用大语言模型将反汇编代码反编译为可读源代码。这在所有分析视图（原生 ARM/x86、Dalvik 字节码、Hermes 字节码）的 **AI 反编译** 标签页中可用。

## 工作原理

当你打开 AI 反编译标签页，Grapefruit 会将函数反汇编发送给 LLM 服务商。提示词包含：

- 函数名和签名（符号表中有时可用）
- 去除装饰性的反汇编——移除地址、管道字符和装饰格式以减少 token 用量
- 对于 Hermes：同时包含基于规则的伪代码和原始字节码，供模型交叉参考

响应实时流式返回，因此你可以看到反编译代码的生成过程。结果在会话期间按函数缓存。

## 支持的服务商

- **Anthropic** — Claude 模型（推荐，代码质量最佳）
- **OpenAI** — GPT 模型
- **Google Gemini**
- **OpenRouter** — 一个 API 接入多种模型

## 配置

启动 Grapefruit 前设置以下环境变量：

```
export LLM_PROVIDER=anthropic
export LLM_API_KEY=sk-ant-...
export LLM_MODEL=claude-sonnet-4-20250514
```

### 各服务商配置示例

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

## 输出语言

AI 反编译器根据输入类型生成不同的语言：

- **原生代码**（ARM、x86）— 反编译为 C/C++
- **Dalvik 字节码**（DEX）— 反编译为 Java
- **Hermes 字节码**（React Native）— 反编译为 JavaScript，重构 React/RN 模式

## 隐私

反汇编通过 HTTPS 发送给你配置的 LLM 服务商。除非主动配置，不会有任何数据流向第三方。此功能完全可选——不配 LLM 也能正常使用 Grapefruit。

## 不使用 LLM

如果未配置 LLM，AI 反编译标签页会显示配置提示。所有其他功能（反汇编、伪代码、CFG、类浏览、Hook 等）都无需 LLM 即可使用。

const KNOWN_ENDPOINTS: Record<string, string> = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com",
  gemini: "https://generativelanguage.googleapis.com",
  openrouter: "https://openrouter.ai/api",
};

type Format = "anthropic" | "gemini" | "openai";

export interface LLMConfig {
  provider: string;
  apiKey: string;
  model: string;
  baseUrl: string;
  format: Format;
}

export function config(): LLMConfig {
  const provider = process.env.LLM_PROVIDER || "";
  const apiKey = process.env.LLM_API_KEY || "";
  const model = process.env.LLM_MODEL || "";
  const baseUrl = process.env.LLM_BASE_URL || KNOWN_ENDPOINTS[provider] || "";
  const format = resolveFormat(provider, baseUrl);
  return { provider, apiKey, model, baseUrl, format };
}

function resolveFormat(provider: string, baseUrl: string): Format {
  if (provider === "anthropic") return "anthropic";
  if (provider === "gemini") return "gemini";
  if (provider in KNOWN_ENDPOINTS) return "openai";
  if (baseUrl) return "openai";
  return "openai";
}

function ensureConfigured(cfg: LLMConfig) {
  if (!cfg.baseUrl || !cfg.model) {
    throw new Error(
      "LLM not configured. Set LLM_PROVIDER (or LLM_BASE_URL) and LLM_MODEL.\n" +
        "Built-in providers: " + Object.keys(KNOWN_ENDPOINTS).join(", ") + "\n" +
        "Custom: set LLM_BASE_URL to any OpenAI-compatible endpoint.",
    );
  }
}

export async function sendText(cfg: LLMConfig, input: string): Promise<string> {
  ensureConfigured(cfg);

  const { url, headers, body } = buildRequest(cfg, input, false);
  const res = await fetch(url, { method: "POST", headers, body });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`LLM request failed (${res.status}): ${text}`);
  }

  const json = await res.json();
  return extractText(cfg.format, json);
}

export async function streamText(
  cfg: LLMConfig,
  input: string,
): Promise<ReadableStream<Uint8Array>> {
  ensureConfigured(cfg);

  // Gemini doesn't support streaming in the same way, fall back to buffered
  if (cfg.format === "gemini") {
    const text = await sendText(cfg, input);
    return new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(text));
        controller.close();
      },
    });
  }

  const { url, headers, body } = buildRequest(cfg, input, true);
  const res = await fetch(url, { method: "POST", headers, body });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`LLM request failed (${res.status}): ${text}`);
  }

  const format = cfg.format;
  const decoder = new TextDecoder();
  let buffer = "";

  return new ReadableStream({
    async start(controller) {
      const reader = res.body!.getReader();
      try {
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n");
          buffer = lines.pop()!;

          for (const line of lines) {
            const trimmed = line.trim();
            if (!trimmed || !trimmed.startsWith("data: ")) continue;
            const payload = trimmed.slice(6);
            if (payload === "[DONE]") continue;

            try {
              const json = JSON.parse(payload);
              const text = extractDelta(format, json);
              if (text) {
                controller.enqueue(new TextEncoder().encode(text));
              }
            } catch {
              // skip malformed SSE chunks
            }
          }
        }
      } catch (e) {
        controller.error(e);
      } finally {
        controller.close();
      }
    },
  });
}

function buildRequest(cfg: LLMConfig, input: string, stream: boolean) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };

  if (cfg.format === "anthropic") {
    headers["x-api-key"] = cfg.apiKey;
    headers["anthropic-version"] = "2023-06-01";
    return {
      url: `${cfg.baseUrl}/v1/messages`,
      headers,
      body: JSON.stringify({
        model: cfg.model,
        max_tokens: 4096,
        stream,
        messages: [{ role: "user", content: input }],
      }),
    };
  }

  if (cfg.format === "gemini") {
    return {
      url: `${cfg.baseUrl}/v1beta/models/${cfg.model}:generateContent?key=${cfg.apiKey}`,
      headers,
      body: JSON.stringify({
        contents: [{ parts: [{ text: input }] }],
      }),
    };
  }

  if (cfg.apiKey) headers["Authorization"] = `Bearer ${cfg.apiKey}`;
  return {
    url: `${cfg.baseUrl}/v1/chat/completions`,
    headers,
    body: JSON.stringify({
      model: cfg.model,
      stream,
      messages: [{ role: "user", content: input }],
    }),
  };
}

function extractText(format: Format, json: unknown): string {
  const data = json as Record<string, unknown>;

  if (format === "anthropic") {
    const content = (data.content as Array<{ type: string; text: string }>)?.[0];
    return content?.text ?? "";
  }

  if (format === "gemini") {
    const candidates = data.candidates as Array<{
      content: { parts: Array<{ text: string }> };
    }>;
    return candidates?.[0]?.content?.parts?.[0]?.text ?? "";
  }

  const choices = data.choices as Array<{ message: { content: string } }>;
  return choices?.[0]?.message?.content ?? "";
}

function extractDelta(format: Format, json: unknown): string {
  const data = json as Record<string, unknown>;

  if (format === "anthropic") {
    if (data.type === "content_block_delta") {
      const delta = data.delta as { type: string; text?: string };
      return delta?.text ?? "";
    }
    return "";
  }

  // openai / openrouter
  const choices = data.choices as Array<{ delta: { content?: string } }>;
  return choices?.[0]?.delta?.content ?? "";
}

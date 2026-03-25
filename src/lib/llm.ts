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

export async function sendText(cfg: LLMConfig, input: string): Promise<string> {
  if (!cfg.baseUrl || !cfg.model) {
    throw new Error(
      "LLM not configured. Set LLM_PROVIDER (or LLM_BASE_URL) and LLM_MODEL.\n" +
        "Built-in providers: " + Object.keys(KNOWN_ENDPOINTS).join(", ") + "\n" +
        "Custom: set LLM_BASE_URL to any OpenAI-compatible endpoint.",
    );
  }

  const { url, headers, body } = buildRequest(cfg, input);
  const res = await fetch(url, { method: "POST", headers, body });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`LLM request failed (${res.status}): ${text}`);
  }

  const json = await res.json();
  return extractText(cfg.format, json);
}

function buildRequest(cfg: LLMConfig, input: string) {
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

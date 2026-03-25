export const endpoints = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com",
  gemini: "https://generativelanguage.googleapis.com",
  openrouter: "https://openrouter.ai/api",
} as const;

export type Provider = keyof typeof endpoints;

export interface LLMConfig {
  provider: Provider;
  apiKey: string;
  model: string;
}

export function config(): LLMConfig {
  const provider = (process.env.LLM_PROVIDER || "") as Provider;
  const apiKey = process.env.LLM_API_KEY || "";
  const model = process.env.LLM_MODEL || "";
  return { provider, apiKey, model };
}

export async function sendText(cfg: LLMConfig, input: string): Promise<string> {
  if (!cfg.provider || !cfg.apiKey || !cfg.model) {
    throw new Error(
      "LLM not configured. Set LLM_PROVIDER, LLM_API_KEY, and LLM_MODEL environment variables.",
    );
  }

  if (!(cfg.provider in endpoints)) {
    throw new Error(
      `Unknown LLM provider: ${cfg.provider}. Supported: ${Object.keys(endpoints).join(", ")}`,
    );
  }

  const { url, headers, body } = buildRequest(cfg, input);
  const res = await fetch(url, { method: "POST", headers, body });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`LLM request failed (${res.status}): ${text}`);
  }

  const json = await res.json();
  return extractText(cfg.provider, json);
}

function buildRequest(cfg: LLMConfig, input: string) {
  const endpoint = endpoints[cfg.provider];
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (cfg.provider === "anthropic") {
    headers["x-api-key"] = cfg.apiKey;
    headers["anthropic-version"] = "2023-06-01";
    return {
      url: `${endpoint}/v1/messages`,
      headers,
      body: JSON.stringify({
        model: cfg.model,
        max_tokens: 4096,
        messages: [{ role: "user", content: input }],
      }),
    };
  }

  if (cfg.provider === "gemini") {
    return {
      url: `${endpoint}/v1beta/models/${cfg.model}:generateContent?key=${cfg.apiKey}`,
      headers,
      body: JSON.stringify({
        contents: [{ parts: [{ text: input }] }],
      }),
    };
  }

  headers["Authorization"] = `Bearer ${cfg.apiKey}`;
  return {
    url: `${endpoint}/v1/chat/completions`,
    headers,
    body: JSON.stringify({
      model: cfg.model,
      messages: [{ role: "user", content: input }],
    }),
  };
}

function extractText(provider: Provider, json: unknown): string {
  const data = json as Record<string, unknown>;

  if (provider === "anthropic") {
    const content = (
      data.content as Array<{ type: string; text: string }>
    )?.[0];
    return content?.text ?? "";
  }

  if (provider === "gemini") {
    const candidates = data.candidates as Array<{
      content: { parts: Array<{ text: string }> };
    }>;
    return candidates?.[0]?.content?.parts?.[0]?.text ?? "";
  }

  const choices = data.choices as Array<{ message: { content: string } }>;
  return choices?.[0]?.message?.content ?? "";
}

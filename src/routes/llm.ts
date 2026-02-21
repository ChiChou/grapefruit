import { styleText } from "node:util";
import { Hono } from "hono";

const provider = (process.env.LLM_PROVIDER || "") as Provider;
const apiKey = process.env.LLM_API_KEY || "";
const model = process.env.LLM_MODEL || "";

const endpoints = {
  anthropic: "https://api.anthropic.com",
  openai: "https://api.openai.com",
  gemini: "https://generativelanguage.googleapis.com",
  openrouter: "https://openrouter.ai/api",
} as const;

type Provider = keyof typeof endpoints;

if (provider) {
  if (!(provider in endpoints)) {
    console.warn(
      "LLM provider not configured or unknown. Set LLM_PROVIDER environment variable to one of: " +
        Object.keys(endpoints).join(", "),
    );
  } else {
    console.debug(styleText("dim", "llm configuration:"));
    console.debug(styleText("yellow", `  provider: ${provider}`));
    console.debug(styleText("yellow", `  model: ${model}`));
  }
}

function buildRequest(input: string) {
  const endpoint = endpoints[provider];
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
  };

  if (provider === "anthropic") {
    headers["x-api-key"] = apiKey;
    headers["anthropic-version"] = "2023-06-01";
    return {
      url: `${endpoint}/v1/messages`,
      headers,
      body: JSON.stringify({
        model,
        max_tokens: 4096,
        messages: [{ role: "user", content: input }],
      }),
    };
  }

  if (provider === "gemini") {
    return {
      url: `${endpoint}/v1beta/models/${model}:generateContent?key=${apiKey}`,
      headers,
      body: JSON.stringify({
        contents: [{ parts: [{ text: input }] }],
      }),
    };
  }

  // openai & openrouter share the same chat completions format
  headers["Authorization"] = `Bearer ${apiKey}`;
  return {
    url: `${endpoint}/v1/chat/completions`,
    headers,
    body: JSON.stringify({
      model,
      messages: [{ role: "user", content: input }],
    }),
  };
}

function extractText(json: unknown): string {
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

  // openai / openrouter
  const choices = data.choices as Array<{
    message: { content: string };
  }>;
  return choices?.[0]?.message?.content ?? "";
}

async function llm(input: string): Promise<string> {
  if (!provider || !apiKey || !model) {
    throw new Error(
      "LLM not configured. Set LLM_PROVIDER, LLM_API_KEY, and LLM_MODEL environment variables.",
    );
  }

  if (!(provider in endpoints)) {
    throw new Error(
      `Unknown LLM provider: ${provider}. Supported: ${Object.keys(endpoints).join(", ")}`,
    );
  }

  const { url, headers, body } = buildRequest(input);

  const res = await fetch(url, { method: "POST", headers, body });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`LLM request failed (${res.status}): ${text}`);
  }

  const json = await res.json();
  return extractText(json);
}

const routes = new Hono().post("/llm", async (c) => {
  const input = await c.req.text();
  if (!input.trim()) return c.text("", 400);

  try {
    return c.text(await llm(input));
  } catch (e) {
    console.error("failed to get LLM response:", e);
    return c.text(e instanceof Error ? e.message : "unknown error", 500);
  }
});

export default routes;

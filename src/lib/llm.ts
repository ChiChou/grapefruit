const endpoint = process.env.LLM_ENDPOINT || "";
const apiKey = process.env.LLM_API_KEY || "";
const model = process.env.LLM_MODEL || "";

type Provider = "anthropic" | "openai" | "gemini" | "openrouter";

function detect(): Provider {
  const url = endpoint.toLowerCase();
  if (url.includes("anthropic")) return "anthropic";
  if (url.includes("generativelanguage.googleapis.com")) return "gemini";
  if (url.includes("openrouter")) return "openrouter";
  return "openai";
}

function buildRequest(provider: Provider, input: string) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };

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

function extractText(provider: Provider, json: unknown): string {
  const data = json as Record<string, unknown>;

  if (provider === "anthropic") {
    const content = (data.content as Array<{ type: string; text: string }>)?.[0];
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

export default async function llm(input: string): Promise<string> {
  if (!endpoint || !apiKey || !model) {
    throw new Error(
      "LLM not configured. Set LLM_ENDPOINT, LLM_API_KEY, and LLM_MODEL environment variables.",
    );
  }

  const provider = detect();
  const { url, headers, body } = buildRequest(provider, input);

  const res = await fetch(url, { method: "POST", headers, body });
  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`LLM request failed (${res.status}): ${text}`);
  }

  const json = await res.json();
  return extractText(provider, json);
}

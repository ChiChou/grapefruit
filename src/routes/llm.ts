import { styleText } from "node:util";
import { Hono } from "hono";
import { config, sendText } from "../lib/llm.ts";

const cfg = config();

if (cfg.baseUrl) {
  console.debug(styleText("dim", "llm configuration:"));
  console.debug(styleText("yellow", `  provider: ${cfg.provider || "custom"}`));
  console.debug(styleText("yellow", `  model: ${cfg.model}`));
  console.debug(styleText("yellow", `  format: ${cfg.format}`));
  if (cfg.provider === "" || !cfg.provider) {
    console.debug(styleText("yellow", `  base_url: ${cfg.baseUrl}`));
  }
}

const routes = new Hono().post("/llm", async (c) => {
  const input = await c.req.text();
  if (!input.trim()) return c.text("", 400);

  try {
    return c.text(await sendText(cfg, input));
  } catch (e) {
    console.error("failed to get LLM response:", e);
    return c.text(e instanceof Error ? e.message : "unknown error", 500);
  }
});

export default routes;

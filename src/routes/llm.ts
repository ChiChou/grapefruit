import { styleText } from "node:util";
import { Hono } from "hono";
import { config, sendText, endpoints } from "../lib/llm.ts";

const cfg = config();

if (cfg.provider) {
  if (!(cfg.provider in endpoints)) {
    console.warn(
      "LLM provider not configured or unknown. Set LLM_PROVIDER environment variable to one of: " +
        Object.keys(endpoints).join(", "),
    );
  } else {
    console.debug(styleText("dim", "llm configuration:"));
    console.debug(styleText("yellow", `  provider: ${cfg.provider}`));
    console.debug(styleText("yellow", `  model: ${cfg.model}`));
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

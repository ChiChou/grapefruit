import { Hono } from "hono";

import llm from "../lib/llm.ts";

const routes = new Hono().post("/llm", async (c) => {
  const input = await c.req.text();
  if (!input.trim()) return c.text("", 400);

  try {
    return c.text(await llm(input));
  } catch (e) {
    return c.text(e instanceof Error ? e.message : "unknown error", 500);
  }
});

export default routes;

import { Hono } from "hono";
import {
  createLiveSession,
  createFileSession,
  getSession,
  closeSession,
  listSessions,
} from "../lib/r2.ts";
import { ansiToHtml } from "../lib/ansi.ts";

const routes = new Hono()
  .get("/r2/sessions", (c) => {
    return c.json(listSessions());
  })
  .post("/r2/open", async (c) => {
    const body = await c.req.json<{
      deviceId: string;
      pid: number;
      arch: string;
      platform: string;
      pointerSize: number;
      pageSize: number;
    }>();

    try {
      const session = await createLiveSession(body);
      return c.json({ id: session.id });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[r2] failed to create live session:", msg);
      return c.json({ error: msg }, 500);
    }
  })
  .post("/r2/open-file", async (c) => {
    const formData = await c.req.formData();
    const file = formData.get("file");
    if (!(file instanceof File)) return c.json({ error: "file required" }, 400);

    try {
      const data = new Uint8Array(await file.arrayBuffer());
      const session = await createFileSession(data, file.name);
      return c.json({ id: session.id });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      console.error("[r2] failed to create file session:", msg);
      return c.json({ error: msg }, 500);
    }
  })
  .post("/r2/:id/cmd", async (c) => {
    const session = getSession(c.req.param("id"));
    if (!session) return c.json({ error: "session not found" }, 404);

    const { command, output } = await c.req.json<{
      command: string;
      output?: "plain" | "html";
    }>();
    if (typeof command !== "string") return c.json({ error: "command required" }, 400);

    try {
      const wantHtml = output === "html";
      session.r2.rawCmd(`e scr.color=${wantHtml ? 3 : 0}`);
      const raw = await session.r2.cmd(command);
      session.r2.rawCmd("e scr.color=0");
      const result = wantHtml ? ansiToHtml(raw) : raw;
      return c.json({ result });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return c.json({ error: msg }, 500);
    }
  })
  .get("/r2/:id/analyze/:address", async (c) => {
    const session = getSession(c.req.param("id"));
    if (!session) return c.json({ error: "session not found" }, 404);

    const address = BigInt(c.req.param("address"));
    try {
      const blocks = await session.r2.analyzeFunction(address);
      return c.json({ blocks });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return c.json({ error: msg }, 500);
    }
  })
  .get("/r2/:id/disassemble/:address", async (c) => {
    const session = getSession(c.req.param("id"));
    if (!session) return c.json({ error: "session not found" }, 404);

    const address = BigInt(c.req.param("address"));
    const output = c.req.query("output") as "plain" | "html" | undefined;
    try {
      const wantHtml = output === "html";
      session.r2.rawCmd(`e scr.color=${wantHtml ? 3 : 0}`);
      const raw = await session.r2.disassembleFunction(address);
      session.r2.rawCmd("e scr.color=0");
      const text = raw && wantHtml ? ansiToHtml(raw) : raw;
      return c.json({ text });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return c.json({ error: msg }, 500);
    }
  })
  .get("/r2/:id/graph/:address", async (c) => {
    const session = getSession(c.req.param("id"));
    if (!session) return c.json({ error: "session not found" }, 404);

    const address = BigInt(c.req.param("address"));
    try {
      const cfg = await session.r2.functionGraph(address);
      return c.json({ cfg });
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return c.json({ error: msg }, 500);
    }
  })
  .delete("/r2/:id", async (c) => {
    const closed = await closeSession(c.req.param("id"));
    if (!closed) return c.json({ error: "session not found" }, 404);
    return c.body(null, 204);
  });

export default routes;

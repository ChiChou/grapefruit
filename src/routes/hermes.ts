import { Hono } from "hono";
import type { Context } from "hono";
import type { HBC } from "r2hermes-wasm";

import { HermesStore } from "../lib/store/hermes.ts";

async function withHBC<T>(c: Context, fn: (hbc: HBC) => T): Promise<T | Response> {
  const deviceId = c.req.param("device")!;
  const identifier = c.req.param("identifier")!;
  const id = parseInt(c.req.param("id")!, 10);

  const store = new HermesStore(deviceId, identifier);
  const blob = store.getBlob(id);
  if (!blob) return c.text("Not found", 404);

  const { HBC } = await import("r2hermes-wasm");
  const hbc = await HBC.fromBuffer(blob.data);
  try {
    return fn(hbc);
  } finally {
    hbc.close();
  }
}

const routes = new Hono()
  .get("/hermes/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const limit = parseInt(c.req.query("limit") || "100", 10);
    const offset = parseInt(c.req.query("offset") || "0", 10);

    try {
      const store = new HermesStore(deviceId, identifier);
      const records = store.query({ limit, offset });
      const total = store.count();

      return c.json({
        logs: records.map((r) => ({
          id: r.id,
          url: r.url,
          hash: r.hash,
          size: r.size,
          createdAt: r.createdAt,
        })),
        total,
        limit,
        offset,
      });
    } catch (e) {
      console.error("Failed to query Hermes records:", e);
      return c.json({ logs: [], total: 0, limit, offset });
    }
  })
  .get("/hermes/:device/:identifier/download/:id", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const id = parseInt(c.req.param("id"), 10);

    try {
      const store = new HermesStore(deviceId, identifier);
      const blob = store.getBlob(id);
      if (!blob) return c.text("Not found", 404);

      const filename = blob.url.split("/").pop() || `hermes-${id}.bin`;
      c.header("Content-Disposition", `attachment; filename="${filename}"`);
      c.header("Content-Type", "application/octet-stream");
      c.header("Content-Length", blob.data.length.toString());
      return c.body(new Uint8Array(blob.data).buffer as ArrayBuffer);
    } catch (e) {
      console.error("Failed to serve Hermes blob:", e);
      return c.text("Failed to serve Hermes blob", 500);
    }
  })
  .get("/hermes/:device/:identifier/analyze/:id", async (c) => {
    try {
      return await withHBC(c, (hbc) =>
        c.json({ info: hbc.info(), functions: hbc.functions(), strings: hbc.strings() }),
      );
    } catch (e) {
      console.error("Failed to analyze Hermes bytecode:", e);
      return c.text("Failed to analyze Hermes bytecode", 500);
    }
  })
  .get("/hermes/:device/:identifier/decompile/:id", async (c) => {
    const fnId = c.req.query("fn");
    const offsets = c.req.query("offsets") === "1";

    try {
      return await withHBC(c, (hbc) => {
        const fid = fnId !== undefined ? parseInt(fnId, 10) : undefined;
        const source = hbc.decompile(fid, { offsets });
        return c.json(fid !== undefined ? { functionId: fid, source } : { source });
      });
    } catch (e) {
      console.error("Failed to decompile Hermes bytecode:", e);
      return c.text("Failed to decompile Hermes bytecode", 500);
    }
  })
  .get("/hermes/:device/:identifier/disassemble/:id", async (c) => {
    const fnId = c.req.query("fn");

    try {
      return await withHBC(c, (hbc) => {
        const fid = fnId !== undefined ? parseInt(fnId, 10) : undefined;
        const raw = hbc.disassemble(fid);
        const source = (raw ?? "")
          .replace(/^Bytecode listing \(asm\):\n*/, "")
          .replace(/^=+\s*$/gm, "")
          .trimEnd();
        return c.json(fid !== undefined ? { functionId: fid, source } : { source });
      });
    } catch (e) {
      console.error("Failed to disassemble Hermes bytecode:", e);
      return c.text("Failed to disassemble Hermes bytecode", 500);
    }
  })
  .delete("/hermes/:device/:identifier/:id", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");
    const id = Number(c.req.param("id"));

    try {
      new HermesStore(deviceId, identifier).rmOne(id);
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to delete Hermes record:", e);
      return c.text("Failed to delete Hermes record", 500);
    }
  })
  .delete("/hermes/:device/:identifier", (c) => {
    const deviceId = c.req.param("device");
    const identifier = c.req.param("identifier");

    try {
      new HermesStore(deviceId, identifier).rm();
      return c.body(null, 204);
    } catch (e) {
      console.error("Failed to clear Hermes records:", e);
      return c.text("Failed to clear Hermes records", 500);
    }
  });

export default routes;

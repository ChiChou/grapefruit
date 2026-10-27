import { Hono } from "hono";
import { Catalog, type Query } from "../lib/signatures.ts";
import { asset } from "../lib/assets.ts";
import lock from "../../signatures.lock.json" with { type: "json" };

let catalog: Catalog | undefined;

export function routes(load: () => Catalog = () => catalog ??= new Catalog(asset("signatures", "signatures.db"), lock.version)) {
  return new Hono().get("/signatures", (c) => {
    const { platform, name, module, arch } = c.req.query();
    if ((platform !== "android" && platform !== "darwin") || !name || name.length > 4096 || (module?.length ?? 0) > 4096 || (arch?.length ?? 0) > 32) {
      return c.json({ error: "Invalid signature lookup" }, 400);
    }
    try {
      const db = load();
      return c.json({ version: db.version, match: db.lookup({ platform, name, module, arch } as Query) });
    } catch (error) {
      console.error("Signature database unavailable:", error);
      return c.json({ error: "Offline signature database unavailable. Enter hook types manually." }, 503);
    }
  });
}

export default routes();

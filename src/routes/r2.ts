import { Hono } from "hono";
import { list } from "../lib/r2.ts";

const routes = new Hono()
  .get("/r2/sessions", (c) => {
    return c.json(list());
  });

export default routes;

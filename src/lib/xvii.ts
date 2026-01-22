/**
 * compatibility layer for frida v16 and v17
 */

import env from "./env.ts";

type FridaModule = typeof import("frida");

const m: FridaModule =
  env.frida === 16
    ? ((await import("frida16")) as unknown as FridaModule)
    : await import("frida");

export type * from "frida";
export default m;

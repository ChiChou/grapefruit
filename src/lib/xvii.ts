/**
 * compatibility layer for frida v16 and v17
 */

import env from "./env.ts";

type FridaModule = typeof import("frida");

const which = env.frida === 16 ? "frida16" : "frida";
const frida: FridaModule = await import(which);

export type * from "frida";
export default frida;

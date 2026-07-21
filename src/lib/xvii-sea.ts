import env from "./env.ts";

type FridaModule = typeof import("frida");

const m = (
  env.frida === 16 ? require("frida16") : require("frida")
) as FridaModule;

export type * from "frida";
export default m;

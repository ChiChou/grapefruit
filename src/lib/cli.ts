import type { ParseArgsConfig } from "node:util";

export const schema: ParseArgsConfig = {
  args: process.argv.slice(2),
  options: {
    frida: { type: "string" },
    host: { type: "string" },
    port: { type: "string" },
    help: { type: "boolean", short: "h" },
    "dry-run": { type: "boolean" },
  },
  allowPositionals: true,
  strict: false,
};

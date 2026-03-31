import fs from "node:fs/promises";
import path from "node:path";
import { parseArgs } from "node:util";

import { schema } from "./cli.ts";

const { values: argv } = parseArgs(schema);

const dev = process.env.NODE_ENV === "development";
const production = process.env.NODE_ENV === "production";

const mapping = {
  frida: "FRIDA_VERSION",
  host: "HOST",
  port: "PORT",
  project: "PROJECT_DIR",
} as const;

for (const [argKey, envKey] of Object.entries(mapping)) {
  if (argv[argKey as keyof typeof mapping] && process.env[envKey]) {
    console.warn(
      `Warning: Both command-line argument '--${argKey}' and environment variable
      '${envKey}' are set. The command-line argument will take precedence.`,
    );
  }
}

const defaultHost = "127.0.0.1";
const host =
  (typeof argv.host === "string" ? argv.host : process.env.HOST) || defaultHost;
const port = parseInt(argv.port as string, 10) || 31337;
const frontend = dev ? 3000 : port;
const envAsNumber = (name: string, defaultValue: number) =>
  parseInt(process.env[name.toUpperCase()] || "0") || defaultValue;

const workdir =
  (typeof argv.project === "string" ? argv.project : process.env.PROJECT_DIR) ||
  path.join(process.cwd(), ".igf");

const frida =
  parseInt(argv.frida as string, 10) || envAsNumber("FRIDA_VERSION", 17);

if (frida !== 16 && frida !== 17)
  throw new Error(`Invalid FRIDA_VERSION ${frida}, must be 16 or 17`);

const { dirname } = import.meta;
const bunSEA =
  process.platform === "win32"
    ? dirname?.includes("\\~BUN\\root")
    : dirname?.includes("/$bunfs/root");

const test = process.env.NODE_ENV === "test";
const noOpen =
  argv["no-open"] === true || process.env.NO_OPEN === "1" || test;

export default {
  bunSEA,
  frida,
  dev,
  production,
  host,
  port: envAsNumber(dev ? "BACKEND_PORT" : "PORT", port),
  frontend: envAsNumber("WEB_PORT", frontend),
  timeout: envAsNumber("FRIDA_TIMEOUT", 1000),
  noOpen,
  workdir,
};

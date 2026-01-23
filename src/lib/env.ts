import { hostname } from "node:os";

const dev = process.env.NODE_ENV === "development";
const production = process.env.NODE_ENV === "production";

const host = dev ? hostname() : "127.0.0.1";
const port = 31337;
const frontend = dev ? 3000 : port;
const envAsNumber = (name: string, defaultValue: number) =>
  parseInt(process.env[name.toUpperCase()] || "0") || defaultValue;
const frida = envAsNumber("FRIDA_VERSION", 17);

if (frida !== 16 && frida !== 17)
  throw new Error("Invalid FRIDA_VERSION, must be 16 or 17");

export default {
  bunSEA: import.meta.dirname?.includes("/$bunfs/root"),
  frida,
  dev,
  production,
  host: process.env.HOST || host,
  port: envAsNumber(dev ? "BACKEND_PORT" : "PORT", port),
  frontend: envAsNumber("WEB_PORT", frontend),
  timeout: envAsNumber("FRIDA_TIMEOUT", 1000),
};

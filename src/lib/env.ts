import { hostname } from "node:os";

const devmode = process.env.NODE_ENV === "development";
const host = devmode ? hostname() : "127.0.0.1";
const port = 31337;
const frontend = devmode ? 3000 : port;

const envAsNumber = (name: string, defaultValue: number) =>
  parseInt(process.env[name.toUpperCase()] || "0") || defaultValue;

export default {
  dev: devmode,
  host: process.env.HOST || host,
  port: envAsNumber(devmode ? "BACKEND_PORT" : "PORT", port),
  frontend: envAsNumber("WEB_PORT", frontend),
  timeout: envAsNumber("FRIDA_TIMEOUT", 1000),
};

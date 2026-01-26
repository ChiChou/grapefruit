import { mkdir } from "node:fs/promises";

const resolve = (relative: string) =>
  new URL(relative, import.meta.url).pathname;

await mkdir(resolve("../agent/dist"), { recursive: true });

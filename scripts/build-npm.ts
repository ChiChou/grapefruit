#!/usr/bin/evn node

import fs from "node:fs/promises";

const resolve = (relative: string) =>
  new URL(relative, import.meta.url).pathname;

await fs.writeFile(resolve("../assets.tgz"), "");

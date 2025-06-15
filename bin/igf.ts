#!/usr/bin/env node --experimental-strip-types --env-file=.env

import type { AddressInfo } from "node:net";

import env from "../server/lib/env.ts";
import server from "../server/index.ts";

server.listen(env.port, env.host, () => {
  const addr = server.address() as AddressInfo;
  console.log(`Server is running on http://${addr.address}:${addr.port}`);
  console.log("environment:", env);
});

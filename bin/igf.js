#!/usr/bin/env node --env-file=.env

import env from "../server/lib/env.ts";
import backend from "../server/index.ts";

backend.listen(env.port, env.host, () => {
  /**
   * @type {import("net").AddressInfo}
   */
  const addr = backend.address();
  console.log(`Server is running on http://${addr.address}:${addr.port}`);
  console.log("environment:", env);
});

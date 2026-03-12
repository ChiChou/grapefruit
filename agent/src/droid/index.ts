import { interfaces, invoke } from "./registry.js";
import * as pins from "./pins.js";
import type { PinRule } from "@/common/pins.js";

import "@/common/encode-arraybuffer.js";

rpc.exports = {
  invoke,
  interfaces,
  restore(rules: PinRule[]) {
    pins.restore(rules);
  },
  snapshot() {
    return pins.snapshot();
  },
};

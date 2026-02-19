import { interfaces, invoke } from "./registry.js";
import * as taps from "./taps.js";
import type { TapRule } from "@/common/taps.js";

import "@/common/encode-arraybuffer.js";

rpc.exports = {
  invoke,
  interfaces,
  restore(rules: TapRule[]) {
    taps.restore(rules);
  },
  snapshot() {
    return taps.snapshot();
  },
};

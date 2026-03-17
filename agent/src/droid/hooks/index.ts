import { createJava, type JavaHookEntry } from "@/common/hooks/group.js";
import * as native from "@/common/hooks/native.js";

import * as clipboard from "./clipboard.js";
import * as broadcast from "./broadcast.js";
import * as intent from "./intent.js";
import * as sharedpref from "./sharedpref.js";
import * as pendingintent from "./pendingintent.js";

const registry = new Map<string, JavaHookEntry>();

registry.set("clipboard", clipboard);
registry.set("broadcast", broadcast);
registry.set("intent", intent);
registry.set("sharedpref", sharedpref);
registry.set("pendingintent", pendingintent);

const { list, status, start, stop } = createJava(registry);
export { list, status, start, stop };

export interface UserHook {
  type: "native";
  module?: string | null;
  name: string;
  sig?: { args: string[]; returns: string };
}

export function userHooks(): UserHook[] {
  return native.list().map(({ module, name, sig }) => ({
    type: "native",
    module,
    name,
    sig,
  }));
}

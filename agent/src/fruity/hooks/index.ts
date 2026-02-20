import { createNative } from "@/common/hooks/group.js";
import * as sqlite from "./sqlite.js";
import * as pasteboard from "./pasteboard.js";
import * as deviceid from "./deviceid.js";
import * as biometric from "./biometric.js";
import * as fileops from "./fileops.js";
import * as firebase from "./firebase.js";
import * as native from "@/common/hooks/native.js";
import * as objc from "./objc.js";

// Available hook groups
const HOOK_GROUPS = [
  "pasteboard",
  "fileops",
  "deviceid",
  "biometric",
  "sqlite",
  "firebase",
] as const;

function get(group: string) {
  if (group === "sqlite") {
    return [
      ...sqlite.open(),
      ...sqlite.bind(),
      ...sqlite.prepare(),
      ...sqlite.exec(),
    ];
  } else if (group === "pasteboard") {
    return [...pasteboard.monitor()];
  } else if (group === "deviceid") {
    return [...deviceid.spoof()];
  } else if (group === "biometric") {
    return [...biometric.bypass()];
  } else if (group === "fileops") {
    return [...fileops.monitor()];
  } else if (group === "firebase") {
    return [...firebase.query(), ...firebase.write()];
  }
}

const { list, status, start, stop } = createNative(HOOK_GROUPS, get);
export { list, status, start, stop };

/**
 * User hook type definition
 */
export interface UserHook {
  type: "objc" | "native";
  module?: string | null;
  cls?: string;
  name: string;
}

/**
 * Get all user-defined hooks (both ObjC and native)
 */
export function userHooks(): UserHook[] {
  const result: UserHook[] = [];

  // Add ObjC hooks
  for (const { cls, sel } of objc.list()) {
    result.push({
      type: "objc",
      cls,
      name: sel,
    });
  }

  // Add native hooks
  for (const { module, name } of native.list()) {
    result.push({
      type: "native",
      module,
      name,
    });
  }

  return result;
}

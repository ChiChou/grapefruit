import * as crypto from "./crypto.js";
import * as sqlite from "./sqlite.js";

const active = new Map<string, InvocationListener[]>();

function get(group: string) {
  if (group === "crypto") {
    return [
      ...crypto.cccrypt(),
      ...crypto.x509(),
      ...crypto.hmac(),
      ...crypto.hash(),
    ];
  } else if (group === "sqlite") {
    return [
      ...sqlite.open(),
      ...sqlite.bind(),
      ...sqlite.prepare(),
      ...sqlite.exec(),
    ];
  }
}

export function start(group: string) {
  if (active.has(group)) return;
  const hooks = get(group);
  if (!hooks) return;
  active.set(group, hooks);
}

export function stop(group: string) {
  const hooks = active.get(group);
  if (!hooks) return;
  for (const hook of hooks) {
    hook.detach();
  }
  active.delete(group);
}

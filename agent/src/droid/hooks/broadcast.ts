import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { patch as createPatch, backtrace } from "@/common/hooks/java.js";
import { toJS } from "@/droid/bridge/object.js";

const restores: Array<() => void> = [];
let running = false;

const patch = createPatch(restores);


function describeIntent(intent: Java.Wrapper): Record<string, unknown> {
  const info: Record<string, unknown> = {};
  try {
    const action = intent.getAction();
    if (action) info.action = action.toString();

    const component = intent.getComponent();
    if (component) info.component = component.flattenToString().toString();

    const data = intent.getDataString();
    if (data) info.data = data.toString();

    const categories = intent.getCategories();
    if (categories && !categories.isEmpty()) {
      const arr: string[] = [];
      const it = categories.iterator();
      let count = 0;
      while (it.hasNext() && count < 16) {
        arr.push(it.next().toString());
        count++;
      }
      info.categories = arr;
    }

    const extras = intent.getExtras();
    if (extras) {
      try {
        const map: Record<string, unknown> = {};
        const keys = extras.keySet();
        const it = keys.iterator();
        let count = 0;
        while (it.hasNext() && count < 32) {
          const key = it.next().toString();
          try {
            map[key] = toJS(extras.get(key));
          } catch {
            map[key] = "<unreadable>";
          }
          count++;
        }
        info.extras = map;
      } catch { /* ignore */ }
    }

    const flags = intent.getFlags();
    if (flags !== 0) info.flags = `0x${(flags >>> 0).toString(16)}`;
  } catch { /* ignore */ }

  return info;
}

function intentSummary(intent: Java.Wrapper): string {
  try {
    const action = intent.getAction()?.toString() ?? "";
    const component = intent.getComponent()?.flattenToString()?.toString() ?? "";
    if (component) return component;
    if (action) return action;
    return intent.toString();
  } catch {
    return "<intent>";
  }
}

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    try {
      hookSendBroadcast();
    } catch (e) {
      console.warn("broadcast: hooks unavailable:", e);
    }
  });
}

function hookSendBroadcast() {
  const ContextWrapper = Java.use("android.content.ContextWrapper");

  // sendBroadcast(Intent)
  patch(
    ContextWrapper.sendBroadcast.overload("android.content.Intent"),
    (original, self, args) => {
      const [intent] = args as [Java.Wrapper];

      send({
        subject: "hook",
        category: "broadcast",
        symbol: "Context.sendBroadcast",
        dir: "enter",
        line: `sendBroadcast(${intentSummary(intent)})`,
        backtrace: backtrace(),
        extra: { op: "send", ...describeIntent(intent) },
      } satisfies BaseMessage);

      return original.call(self, intent);
    },
  );

  // sendBroadcast(Intent, String) - with permission
  try {
    patch(
      ContextWrapper.sendBroadcast.overload(
        "android.content.Intent",
        "java.lang.String",
      ),
      (original, self, args) => {
        const [intent, perm] = args as [Java.Wrapper, Java.Wrapper | null];

        send({
          subject: "hook",
          category: "broadcast",
          symbol: "Context.sendBroadcast",
          dir: "enter",
          line: `sendBroadcast(${intentSummary(intent)}, ${perm?.toString() ?? "null"})`,
          backtrace: backtrace(),
          extra: {
            op: "send",
            permission: perm?.toString() ?? null,
            ...describeIntent(intent),
          },
        } satisfies BaseMessage);

        return original.call(self, intent, perm);
      },
    );
  } catch { /* overload may not exist */ }

  // sendOrderedBroadcast(Intent, String)
  try {
    patch(
      ContextWrapper.sendOrderedBroadcast.overload(
        "android.content.Intent",
        "java.lang.String",
      ),
      (original, self, args) => {
        const [intent, perm] = args as [Java.Wrapper, Java.Wrapper | null];

        send({
          subject: "hook",
          category: "broadcast",
          symbol: "Context.sendOrderedBroadcast",
          dir: "enter",
          line: `sendOrderedBroadcast(${intentSummary(intent)})`,
          backtrace: backtrace(),
          extra: {
            op: "sendOrdered",
            permission: perm?.toString() ?? null,
            ...describeIntent(intent),
          },
        } satisfies BaseMessage);

        return original.call(self, intent, perm);
      },
    );
  } catch { /* overload may not exist */ }

  // sendStickyBroadcast(Intent)
  try {
    patch(
      ContextWrapper.sendStickyBroadcast.overload("android.content.Intent"),
      (original, self, args) => {
        const [intent] = args as [Java.Wrapper];

        send({
          subject: "hook",
          category: "broadcast",
          symbol: "Context.sendStickyBroadcast",
          dir: "enter",
          line: `sendStickyBroadcast(${intentSummary(intent)})`,
          backtrace: backtrace(),
          extra: { op: "sendSticky", ...describeIntent(intent) },
        } satisfies BaseMessage);

        return original.call(self, intent);
      },
    );
  } catch { /* may not exist on all API levels */ }

  // registerReceiver(BroadcastReceiver, IntentFilter)
  try {
    patch(
      ContextWrapper.registerReceiver.overload(
        "android.content.BroadcastReceiver",
        "android.content.IntentFilter",
      ),
      (original, self, args) => {
        const [receiver, filter] = args as [Java.Wrapper, Java.Wrapper];

        const actions: string[] = [];
        try {
          const count = filter.countActions();
          for (let i = 0; i < count && i < 32; i++) {
            actions.push(filter.getAction(i).toString());
          }
        } catch { /* ignore */ }

        send({
          subject: "hook",
          category: "broadcast",
          symbol: "Context.registerReceiver",
          dir: "enter",
          line: `registerReceiver(${actions.join(", ") || "..."})`,
          backtrace: backtrace(),
          extra: {
            op: "register",
            receiverClass: receiver?.$className ?? null,
            actions,
          },
        } satisfies BaseMessage);

        return original.call(self, receiver, filter);
      },
    );
  } catch { /* overload may not exist */ }

  // unregisterReceiver(BroadcastReceiver)
  try {
    patch(
      ContextWrapper.unregisterReceiver.overload(
        "android.content.BroadcastReceiver",
      ),
      (original, self, args) => {
        const [receiver] = args as [Java.Wrapper];

        send({
          subject: "hook",
          category: "broadcast",
          symbol: "Context.unregisterReceiver",
          dir: "enter",
          line: `unregisterReceiver(${receiver?.$className ?? "..."})`,
          backtrace: backtrace(),
          extra: {
            op: "unregister",
            receiverClass: receiver?.$className ?? null,
          },
        } satisfies BaseMessage);

        return original.call(self, receiver);
      },
    );
  } catch { /* overload may not exist */ }
}

export function stop() {
  Java.perform(() => {
    for (let i = restores.length - 1; i >= 0; i--) {
      try {
        restores[i]();
      } catch { /* ignore */ }
    }
  });
  restores.length = 0;
  running = false;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  if (!Java.available) return false;
  let found = false;
  Java.perform(() => {
    try {
      Java.use("android.content.ContextWrapper");
      found = true;
    } catch { /* not found */ }
  });
  return found;
}

import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { hook, bt } from "@/common/hooks/java.js";
import { toJS } from "@/droid/bridge/object.js";

const hooks: InvocationListener[] = [];
let running = false;

function describeIntent(intent: Java.Wrapper): Record<string, unknown> {
  const info: Record<string, unknown> = {};
  try {
    const action = intent.getAction();
    if (action) info.action = action.toString();

    const component = intent.getComponent();
    if (component) info.component = component.flattenToString().toString();

    const data = intent.getDataString();
    if (data) info.data = data.toString();

    const type = intent.getType();
    if (type) info.type = type.toString();

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
      } catch {
        /* ignore */
      }
    }

    const flags = intent.getFlags();
    if (flags !== 0) info.flags = `0x${(flags >>> 0).toString(16)}`;
  } catch {
    /* ignore */
  }

  return info;
}

function intentSummary(intent: Java.Wrapper): string {
  try {
    const component = intent.getComponent()?.flattenToString()?.toString();
    if (component) return component;
    const action = intent.getAction()?.toString();
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
      hookActivityStart();
    } catch (e) {
      console.warn("intent: Activity hooks unavailable:", e);
    }

    try {
      hookServiceStart();
    } catch (e) {
      console.warn("intent: Service hooks unavailable:", e);
    }
  });
}

function hookActivityStart() {
  const Activity = Java.use("android.app.Activity");

  // startActivity(Intent)
  hooks.push(
    hook(
      Activity.startActivity.overload("android.content.Intent"),
      (original, self, args) => {
        const [intent] = args as [Java.Wrapper];

        send({
          subject: "hook",
          category: "intent",
          symbol: "Activity.startActivity",
          dir: "enter",
          line: `startActivity(${intentSummary(intent)})`,
          backtrace: bt(),
          extra: {
            op: "startActivity",
            caller: self.$className,
            ...describeIntent(intent),
          },
        } satisfies BaseMessage);

        return original.call(self, intent);
      },
    ),
  );

  // startActivity(Intent, Bundle)
  try {
    hooks.push(
      hook(
        Activity.startActivity.overload(
          "android.content.Intent",
          "android.os.Bundle",
        ),
        (original, self, args) => {
          const [intent, options] = args as [Java.Wrapper, Java.Wrapper | null];

          send({
            subject: "hook",
            category: "intent",
            symbol: "Activity.startActivity",
            dir: "enter",
            line: `startActivity(${intentSummary(intent)}, options)`,
            backtrace: bt(),
            extra: {
              op: "startActivity",
              caller: self.$className,
              ...describeIntent(intent),
            },
          } satisfies BaseMessage);

          return original.call(self, intent, options);
        },
      ),
    );
  } catch {
    /* overload may not exist */
  }

  // startActivityForResult(Intent, int)
  try {
    hooks.push(
      hook(
        Activity.startActivityForResult.overload(
          "android.content.Intent",
          "int",
        ),
        (original, self, args) => {
          const [intent, requestCode] = args as [Java.Wrapper, number];

          send({
            subject: "hook",
            category: "intent",
            symbol: "Activity.startActivityForResult",
            dir: "enter",
            line: `startActivityForResult(${intentSummary(intent)}, ${requestCode})`,
            backtrace: bt(),
            extra: {
              op: "startActivityForResult",
              caller: self.$className,
              requestCode,
              ...describeIntent(intent),
            },
          } satisfies BaseMessage);

          return original.call(self, intent, requestCode);
        },
      ),
    );
  } catch {
    /* overload may not exist */
  }

  // startActivityForResult(Intent, int, Bundle)
  try {
    hooks.push(
      hook(
        Activity.startActivityForResult.overload(
          "android.content.Intent",
          "int",
          "android.os.Bundle",
        ),
        (original, self, args) => {
          const [intent, requestCode, options] = args as [
            Java.Wrapper,
            number,
            Java.Wrapper | null,
          ];

          send({
            subject: "hook",
            category: "intent",
            symbol: "Activity.startActivityForResult",
            dir: "enter",
            line: `startActivityForResult(${intentSummary(intent)}, ${requestCode}, options)`,
            backtrace: bt(),
            extra: {
              op: "startActivityForResult",
              caller: self.$className,
              requestCode,
              ...describeIntent(intent),
            },
          } satisfies BaseMessage);

          return original.call(self, intent, requestCode, options);
        },
      ),
    );
  } catch {
    /* overload may not exist */
  }
}

function hookServiceStart() {
  const ContextWrapper = Java.use("android.content.ContextWrapper");

  // startService(Intent)
  hooks.push(
    hook(
      ContextWrapper.startService.overload("android.content.Intent"),
      (original, self, args) => {
        const [intent] = args as [Java.Wrapper];

        send({
          subject: "hook",
          category: "intent",
          symbol: "Context.startService",
          dir: "enter",
          line: `startService(${intentSummary(intent)})`,
          backtrace: bt(),
          extra: {
            op: "startService",
            caller: self.$className,
            ...describeIntent(intent),
          },
        } satisfies BaseMessage);

        return original.call(self, intent);
      },
    ),
  );

  // stopService(Intent)
  try {
    hooks.push(
      hook(
        ContextWrapper.stopService.overload("android.content.Intent"),
        (original, self, args) => {
          const [intent] = args as [Java.Wrapper];

          send({
            subject: "hook",
            category: "intent",
            symbol: "Context.stopService",
            dir: "enter",
            line: `stopService(${intentSummary(intent)})`,
            backtrace: bt(),
            extra: {
              op: "stopService",
              caller: self.$className,
              ...describeIntent(intent),
            },
          } satisfies BaseMessage);

          return original.call(self, intent);
        },
      ),
    );
  } catch {
    /* overload may not exist */
  }

  // bindService(Intent, ServiceConnection, int)
  try {
    hooks.push(
      hook(
        ContextWrapper.bindService.overload(
          "android.content.Intent",
          "android.content.ServiceConnection",
          "int",
        ),
        (original, self, args) => {
          const [intent, conn, flags] = args as [
            Java.Wrapper,
            Java.Wrapper,
            number,
          ];

          send({
            subject: "hook",
            category: "intent",
            symbol: "Context.bindService",
            dir: "enter",
            line: `bindService(${intentSummary(intent)}, flags=0x${(flags >>> 0).toString(16)})`,
            backtrace: bt(),
            extra: {
              op: "bindService",
              caller: self.$className,
              flags: `0x${(flags >>> 0).toString(16)}`,
              ...describeIntent(intent),
            },
          } satisfies BaseMessage);

          return original.call(self, intent, conn, flags);
        },
      ),
    );
  } catch {
    /* overload may not exist */
  }

  // startForegroundService(Intent)
  try {
    hooks.push(
      hook(
        ContextWrapper.startForegroundService.overload(
          "android.content.Intent",
        ),
        (original, self, args) => {
          const [intent] = args as [Java.Wrapper];

          send({
            subject: "hook",
            category: "intent",
            symbol: "Context.startForegroundService",
            dir: "enter",
            line: `startForegroundService(${intentSummary(intent)})`,
            backtrace: bt(),
            extra: {
              op: "startForegroundService",
              caller: self.$className,
              ...describeIntent(intent),
            },
          } satisfies BaseMessage);

          return original.call(self, intent);
        },
      ),
    );
  } catch {
    /* may not exist on older API levels */
  }
}

export function stop() {
  for (const h of hooks) {
    try {
      h.detach();
    } catch {
      /* ignore */
    }
  }
  hooks.length = 0;
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
      Java.use("android.app.Activity");
      found = true;
    } catch {
      /* not found */
    }
  });
  return found;
}

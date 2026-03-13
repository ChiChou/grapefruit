import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { hook, bt } from "@/common/hooks/java.js";

const hooks: InvocationListener[] = [];
let running = false;

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    try {
      hookClipboardManager();
    } catch (e) {
      console.warn("clipboard: hooks unavailable:", e);
    }
  });
}

function hookClipboardManager() {
  const ClipboardManager = Java.use("android.content.ClipboardManager");

  // getPrimaryClip
  hooks.push(
    hook(ClipboardManager.getPrimaryClip, (original, self, args) => {
      const ret = original.call(self, ...args) as Java.Wrapper | null;

      let text: string | null = null;
      try {
        if (ret && ret.getItemCount() > 0) {
          const item = ret.getItemAt(0);
          const t = item.getText();
          if (t) text = t.toString();
        }
      } catch {
        /* ignore */
      }

      send({
        subject: "hook",
        category: "clipboard",
        symbol: "ClipboardManager.getPrimaryClip",
        dir: "leave",
        line: "getPrimaryClip() // read",
        backtrace: bt(),
        extra: { op: "read", text },
      } satisfies BaseMessage);

      return ret;
    }),
  );

  // getPrimaryClipDescription
  try {
    hooks.push(
      hook(
        ClipboardManager.getPrimaryClipDescription,
        (original, self, args) => {
          const ret = original.call(self, ...args);

          send({
            subject: "hook",
            category: "clipboard",
            symbol: "ClipboardManager.getPrimaryClipDescription",
            dir: "leave",
            line: "getPrimaryClipDescription() // read",
            backtrace: bt(),
            extra: { op: "read" },
          } satisfies BaseMessage);

          return ret;
        },
      ),
    );
  } catch {
    /* overload may not exist */
  }

  // getText (deprecated but still used)
  try {
    hooks.push(
      hook(ClipboardManager.getText, (original, self, args) => {
        const ret = original.call(self, ...args) as Java.Wrapper | null;
        const text = ret?.toString() ?? null;

        send({
          subject: "hook",
          category: "clipboard",
          symbol: "ClipboardManager.getText",
          dir: "leave",
          line: "getText() // read",
          backtrace: bt(),
          extra: { op: "read", text },
        } satisfies BaseMessage);

        return ret;
      }),
    );
  } catch {
    /* may not exist */
  }

  // setPrimaryClip
  hooks.push(
    hook(
      ClipboardManager.setPrimaryClip.overload("android.content.ClipData"),
      (original, self, args) => {
        const [clip] = args as [Java.Wrapper];

        let text: string | null = null;
        let label: string | null = null;
        try {
          label = clip.getDescription().getLabel()?.toString() ?? null;
          if (clip.getItemCount() > 0) {
            const item = clip.getItemAt(0);
            const t = item.getText();
            if (t) text = t.toString();
          }
        } catch {
          /* ignore */
        }

        send({
          subject: "hook",
          category: "clipboard",
          symbol: "ClipboardManager.setPrimaryClip",
          dir: "enter",
          line: `setPrimaryClip(${label ? `"${label}"` : "..."}) // write`,
          backtrace: bt(),
          extra: { op: "write", label, text },
        } satisfies BaseMessage);

        return original.call(self, clip);
      },
    ),
  );

  // setText (deprecated but still used)
  try {
    hooks.push(
      hook(
        ClipboardManager.setText.overload("java.lang.CharSequence"),
        (original, self, args) => {
          const [text] = args as [Java.Wrapper];
          const str = text?.toString() ?? null;

          send({
            subject: "hook",
            category: "clipboard",
            symbol: "ClipboardManager.setText",
            dir: "enter",
            line: "setText(...) // write",
            backtrace: bt(),
            extra: { op: "write", text: str },
          } satisfies BaseMessage);

          return original.call(self, text);
        },
      ),
    );
  } catch {
    /* may not exist */
  }

  // hasPrimaryClip
  try {
    hooks.push(
      hook(ClipboardManager.hasPrimaryClip, (original, self, args) => {
        const ret = original.call(self, ...args);

        send({
          subject: "hook",
          category: "clipboard",
          symbol: "ClipboardManager.hasPrimaryClip",
          dir: "leave",
          line: `hasPrimaryClip() => ${ret} // query`,
          backtrace: bt(),
          extra: { op: "query", result: ret },
        } satisfies BaseMessage);

        return ret;
      }),
    );
  } catch {
    /* may not exist */
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
      Java.use("android.content.ClipboardManager");
      found = true;
    } catch {
      /* not found */
    }
  });
  return found;
}

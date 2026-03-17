import Java from "frida-java-bridge";

import type { BaseMessage } from "@/common/hooks/context.js";
import { hook, bt } from "@/common/hooks/java.js";

const hooks: InvocationListener[] = [];
let running = false;

// PendingIntent flags
const FLAG_IMMUTABLE = 0x04000000;

function describeIntent(intent: Java.Wrapper): Record<string, unknown> {
  const info: Record<string, unknown> = {};
  try {
    const action = intent.getAction();
    if (action) info.action = action.toString();

    const component = intent.getComponent();
    if (component) info.component = component.flattenToString().toString();

    const data = intent.getDataString();
    if (data) info.data = data.toString();

    const flags = intent.getFlags();
    if (flags !== 0) info.intentFlags = `0x${(flags >>> 0).toString(16)}`;
  } catch {
    /* ignore */
  }
  return info;
}

function analyzeRisk(
  intent: Java.Wrapper,
  flags: number,
): { risk: string; warnings: string[] } {
  const warnings: string[] = [];
  const isImmutable = (flags & FLAG_IMMUTABLE) !== 0;
  let isImplicit = false;

  try {
    isImplicit = intent.getComponent() === null;
  } catch {
    /* ignore */
  }

  if (!isImmutable) warnings.push("Missing FLAG_IMMUTABLE");
  if (isImplicit) warnings.push("Implicit intent (hijack risk)");

  const risk =
    warnings.length >= 2
      ? "critical"
      : warnings.length === 1
        ? "high"
        : "info";
  return { risk, warnings };
}

function formatFlags(flags: number): string {
  return `0x${(flags >>> 0).toString(16)}`;
}

function hookPendingIntentMethod(
  PendingIntent: Java.Wrapper,
  methodName: string,
  type: string,
  overloadArgs: string[],
) {
  hooks.push(
    hook(
      PendingIntent[methodName].overload(...overloadArgs),
      (original, self, args) => {
        const [, requestCode, intent, flags] = args as [
          Java.Wrapper,
          number,
          Java.Wrapper,
          number,
        ];

        const { risk, warnings } = analyzeRisk(intent, flags);
        const intentInfo = describeIntent(intent);
        const warningStr =
          warnings.length > 0 ? ` \u26a0\ufe0f ${warnings.join(", ")}` : "";

        send({
          subject: "hook",
          category: "pendingintent",
          symbol: `PendingIntent.${methodName}`,
          dir: "enter",
          line: `PendingIntent.${methodName}(requestCode=${requestCode}, flags=${formatFlags(flags)})${warningStr}`,
          backtrace: bt(),
          extra: {
            type,
            requestCode,
            flags: formatFlags(flags),
            risk,
            warnings,
            ...intentInfo,
          },
        } satisfies BaseMessage);

        return original.call(self, ...args);
      },
    ),
  );
}

function hookGetActivity() {
  const PendingIntent = Java.use("android.app.PendingIntent");

  // getActivity(Context, int, Intent, int)
  hookPendingIntentMethod(PendingIntent, "getActivity", "activity", [
    "android.content.Context",
    "int",
    "android.content.Intent",
    "int",
  ]);

  // getActivity(Context, int, Intent, int, Bundle)
  try {
    hookPendingIntentMethod(PendingIntent, "getActivity", "activity", [
      "android.content.Context",
      "int",
      "android.content.Intent",
      "int",
      "android.os.Bundle",
    ]);
  } catch {
    /* overload may not exist */
  }
}

function hookGetService() {
  const PendingIntent = Java.use("android.app.PendingIntent");

  // getService(Context, int, Intent, int)
  hookPendingIntentMethod(PendingIntent, "getService", "service", [
    "android.content.Context",
    "int",
    "android.content.Intent",
    "int",
  ]);
}

function hookGetBroadcast() {
  const PendingIntent = Java.use("android.app.PendingIntent");

  // getBroadcast(Context, int, Intent, int)
  hookPendingIntentMethod(PendingIntent, "getBroadcast", "broadcast", [
    "android.content.Context",
    "int",
    "android.content.Intent",
    "int",
  ]);
}

function hookGetForegroundService() {
  const PendingIntent = Java.use("android.app.PendingIntent");

  // getForegroundService(Context, int, Intent, int) - API 26+
  hookPendingIntentMethod(
    PendingIntent,
    "getForegroundService",
    "foregroundService",
    [
      "android.content.Context",
      "int",
      "android.content.Intent",
      "int",
    ],
  );
}

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    try {
      hookGetActivity();
    } catch (e) {
      console.warn("pendingintent: getActivity hooks unavailable:", e);
    }
    try {
      hookGetService();
    } catch (e) {
      console.warn("pendingintent: getService hooks unavailable:", e);
    }
    try {
      hookGetBroadcast();
    } catch (e) {
      console.warn("pendingintent: getBroadcast hooks unavailable:", e);
    }
    try {
      hookGetForegroundService();
    } catch (e) {
      console.warn("pendingintent: getForegroundService hooks unavailable:", e);
    }
  });
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
      Java.use("android.app.PendingIntent");
      found = true;
    } catch {
      /* not found */
    }
  });
  return found;
}

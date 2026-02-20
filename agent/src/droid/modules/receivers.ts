import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";
import { getContext } from "@/droid/lib/context.js";
import { buildIntent, type IntentOptions } from "@/droid/lib/intent.js";

export type { IntentOptions as BroadcastOptions };

export interface ReceiverEntry {
  name: string;
  exported: boolean;
  permission: string | null;
}

export function list() {
  return perform(() => {
    const PackageManager = Java.use("android.content.pm.PackageManager");

    const context = getContext();
    const pm = context.getPackageManager();
    const pkg = pm.getPackageInfo(
      context.getPackageName(),
      PackageManager.GET_RECEIVERS.value,
    );

    const result: ReceiverEntry[] = [];
    const receivers = pkg.receivers?.value;
    if (receivers) {
      for (let i = 0; i < receivers.length; i++) {
        const r = receivers[i];
        result.push({
          name: r.name?.value || "",
          exported: !!r.exported?.value,
          permission: r.permission?.value || null,
        });
      }
    }

    return result;
  });
}

export function send(options: IntentOptions) {
  return perform(() => {
    const intent = buildIntent(options);
    getContext().sendBroadcast(intent);
  });
}

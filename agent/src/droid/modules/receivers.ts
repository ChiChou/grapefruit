import Java from "frida-java-bridge";

import { getContext } from "../lib/context.js";
import { buildIntent, type IntentOptions } from "../lib/intent.js";

export type { IntentOptions as BroadcastOptions };

export interface ReceiverEntry {
  name: string;
  exported: boolean;
  permission: string | null;
}

export function list() {
  return new Promise<ReceiverEntry[]>((resolve) => {
    Java.perform(() => {
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

      resolve(result);
    });
  });
}

export function send(options: IntentOptions) {
  return new Promise<void>((resolve, reject) => {
    Java.perform(() => {
      try {
        const intent = buildIntent(options);
        getContext().sendBroadcast(intent);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
}

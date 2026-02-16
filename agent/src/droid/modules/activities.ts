import Java from "frida-java-bridge";

import { getContext } from "../lib/context.js";
import { buildIntent, type IntentOptions } from "../lib/intent.js";

export type { IntentOptions };

export interface ActivityEntry {
  name: string;
  exported: boolean;
  permission: string | null;
  targetActivity: string | null;
}

export function list() {
  return new Promise<ActivityEntry[]>((resolve) => {
    Java.perform(() => {
      const PackageManager = Java.use("android.content.pm.PackageManager");

      const context = getContext();
      const pm = context.getPackageManager();
      const pkg = pm.getPackageInfo(
        context.getPackageName(),
        PackageManager.GET_ACTIVITIES.value,
      );

      const result: ActivityEntry[] = [];
      const activities = pkg.activities?.value;
      if (activities) {
        for (let i = 0; i < activities.length; i++) {
          const a = activities[i];
          result.push({
            name: a.name?.value || "",
            exported: !!a.exported?.value,
            permission: a.permission?.value || null,
            targetActivity: a.targetActivity?.value || null,
          });
        }
      }

      resolve(result);
    });
  });
}

export function start(options: IntentOptions) {
  return new Promise<void>((resolve, reject) => {
    Java.perform(() => {
      try {
        const Intent = Java.use("android.content.Intent");
        const intent = buildIntent(options);
        if (options.flags === undefined) {
          intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK.value);
        }
        getContext().startActivity(intent);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
}

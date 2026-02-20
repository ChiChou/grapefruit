import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";
import { getContext } from "@/droid/lib/context.js";
import { buildIntent, type IntentOptions } from "@/droid/lib/intent.js";

export type { IntentOptions };

export interface ServiceEntry {
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
      PackageManager.GET_SERVICES.value,
    );

    const result: ServiceEntry[] = [];
    const services = pkg.services?.value;
    if (services) {
      for (let i = 0; i < services.length; i++) {
        const s = services[i];
        result.push({
          name: s.name?.value || "",
          exported: !!s.exported?.value,
          permission: s.permission?.value || null,
        });
      }
    }

    return result;
  });
}

export function start(options: IntentOptions) {
  return perform(() => {
    const intent = buildIntent(options);
    getContext().startService(intent);
  });
}

export function stop(options: IntentOptions) {
  return perform(() => {
    const intent = buildIntent(options);
    return getContext().stopService(intent) as boolean;
  });
}

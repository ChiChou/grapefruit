import Java from "frida-java-bridge";

import { getContext } from "../lib/context.js";
import { buildIntent, type IntentOptions } from "../lib/intent.js";

export type { IntentOptions };

export interface ServiceEntry {
  name: string;
  exported: boolean;
  permission: string | null;
}

export function list() {
  return new Promise<ServiceEntry[]>((resolve) => {
    Java.perform(() => {
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

      resolve(result);
    });
  });
}

export function start(options: IntentOptions) {
  return new Promise<void>((resolve, reject) => {
    Java.perform(() => {
      try {
        const intent = buildIntent(options);
        getContext().startService(intent);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
}

export function stop(options: IntentOptions) {
  return new Promise<boolean>((resolve, reject) => {
    Java.perform(() => {
      try {
        const intent = buildIntent(options);
        const stopped: boolean = getContext().stopService(intent);
        resolve(stopped);
      } catch (e) {
        reject(e);
      }
    });
  });
}

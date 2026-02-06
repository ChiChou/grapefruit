import Java from "frida-java-bridge";

export interface ServiceEntry {
  name: string;
  exported: boolean;
  permission: string | null;
}

export interface IntentOptions {
  action?: string;
  component?: string;
  data?: string;
  categories?: string[];
  extras?: Record<string, string | number | boolean>;
}

function getContext() {
  const ActivityThread = Java.use("android.app.ActivityThread");
  return ActivityThread.currentApplication().getApplicationContext();
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

function buildIntent(options: IntentOptions): Java.Wrapper {
  const Intent = Java.use("android.content.Intent");
  const ComponentName = Java.use("android.content.ComponentName");
  const Uri = Java.use("android.net.Uri");

  const intent = Intent.$new();

  if (options.action) intent.setAction(options.action);

  if (options.component) {
    const parts = options.component.split("/");
    if (parts.length === 2) {
      intent.setComponent(ComponentName.$new(parts[0], parts[1]));
    }
  }

  if (options.data) intent.setData(Uri.parse(options.data));

  if (options.categories) {
    for (const cat of options.categories) {
      intent.addCategory(cat);
    }
  }

  if (options.extras) {
    for (const [key, value] of Object.entries(options.extras)) {
      if (typeof value === "string") {
        intent.putExtra(key, Java.use("java.lang.String").$new(value));
      } else if (typeof value === "number") {
        intent.putExtra(key, Java.use("java.lang.Integer").$new(value));
      } else if (typeof value === "boolean") {
        intent.putExtra(key, Java.use("java.lang.Boolean").$new(value));
      }
    }
  }

  return intent;
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

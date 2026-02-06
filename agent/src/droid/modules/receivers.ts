import Java from "frida-java-bridge";

export interface ReceiverEntry {
  name: string;
  exported: boolean;
  permission: string | null;
}

export interface BroadcastOptions {
  action?: string;
  component?: string;
  data?: string;
  categories?: string[];
  extras?: Record<string, string | number | boolean>;
  mimeType?: string;
}

function getContext() {
  const ActivityThread = Java.use("android.app.ActivityThread");
  return ActivityThread.currentApplication().getApplicationContext();
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

export function send(options: BroadcastOptions) {
  return new Promise<void>((resolve, reject) => {
    Java.perform(() => {
      try {
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

        if (options.mimeType) {
          if (options.data) {
            intent.setDataAndType(Uri.parse(options.data), options.mimeType);
          } else {
            intent.setType(options.mimeType);
          }
        }

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

        getContext().sendBroadcast(intent);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
}

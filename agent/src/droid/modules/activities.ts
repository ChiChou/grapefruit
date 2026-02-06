import Java from "frida-java-bridge";

export interface ActivityEntry {
  name: string;
  exported: boolean;
  permission: string | null;
  targetActivity: string | null;
}

export interface IntentOptions {
  action?: string;
  component?: string;
  data?: string;
  categories?: string[];
  extras?: Record<string, string | number | boolean>;
  flags?: number;
  mimeType?: string;
}

function getContext() {
  const ActivityThread = Java.use("android.app.ActivityThread");
  return ActivityThread.currentApplication().getApplicationContext();
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
        const ComponentName = Java.use("android.content.ComponentName");
        const Uri = Java.use("android.net.Uri");

        const intent = Intent.$new();

        if (options.action) {
          intent.setAction(options.action);
        }

        if (options.component) {
          const parts = options.component.split("/");
          if (parts.length === 2) {
            intent.setComponent(ComponentName.$new(parts[0], parts[1]));
          }
        }

        if (options.data) {
          intent.setData(Uri.parse(options.data));
        }

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

        const flagValue = options.flags ?? Intent.FLAG_ACTIVITY_NEW_TASK.value;
        intent.setFlags(flagValue);

        getContext().startActivity(intent);
        resolve();
      } catch (e) {
        reject(e);
      }
    });
  });
}

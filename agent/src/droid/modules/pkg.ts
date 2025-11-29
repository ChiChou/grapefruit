export interface PackageInfo {
  name: string;
  version: string;
  ver: number;
  activities: ActivityInfo[];
  services: ServiceInfo[];
  permissions: string[];
}

export interface UrlSchemeInfo {
  schemes: string[];
  browsable: boolean;
  isDefault: boolean;
}

export interface ActivityInfo {
  name: string;
  label?: string;
  urls?: UrlSchemeInfo[];
  permission?: string;
  screenOrientation?: number;
}

export interface ServiceInfo {
  name: string;
  exported?: boolean;
  permission?: string;
}

export function info() {
  return new Promise<PackageInfo>((resolve) => {
    Java.perform(() => {
      const PackageManager = Java.use("android.content.pm.PackageManager");
      const ActivityThread = Java.use("android.app.ActivityThread");
      const Intent = Java.use("android.content.Intent");
      const PackageManager$ResolveInfoFlags = Java.use(
        "android.content.pm.PackageManager$ResolveInfoFlags",
      );
      const VERSION = Java.use("android.os.Build$VERSION");

      const context =
        ActivityThread.currentApplication().getApplicationContext();
      const pm = context.getPackageManager();
      const pkgInfo = pm.getPackageInfo(
        context.getPackageName(),
        PackageManager.GET_ACTIVITIES.value |
          PackageManager.GET_SERVICES.value |
          PackageManager.GET_RECEIVERS.value |
          PackageManager.GET_PERMISSIONS.value |
          PackageManager.GET_SHARED_LIBRARY_FILES.value,
      );

      {
        const intent = Intent.$new(Intent.ACTION_VIEW.value);
        const resolveInfoList =
          VERSION.SDK_INT.value >= 33
            ? pm.queryIntentActivities(
                intent,
                PackageManager$ResolveInfoFlags.of(
                  PackageManager.MATCH_ALL.value,
                ),
              )
            : pm.queryIntentActivities(intent, PackageManager.MATCH_ALL.value);

        for (let i = 0; i < resolveInfoList.size(); i++) {
          const resolveInfo = resolveInfoList.get(i);
          console.log(resolveInfo);
        }
      }

      const result: PackageInfo = {
        name: pkgInfo.packageName.value,
        version: pkgInfo.versionName.value,
        ver: pkgInfo.getLongVersionCode().value,
        activities: [],
        services: [],
        permissions: [],
      };

      const activities = pkgInfo.activities.value;
      if (activities) {
        for (let i = 0; i < activities.length; i++) {
          const activity = activities[i];
          result.activities.push({
            name: activity.name?.value,
            label: activity.label?.value,
            permission: activity.permission?.value,
            screenOrientation: activity.screenOrientation?.value,
          });
        }
      }

      const services = pkgInfo.services.value;
      if (services) {
        for (let i = 0; i < services.length; i++) {
          const service = services[i];
          const item: ServiceInfo = {
            name: service.name.value,
          };

          if (service.exported.value) item.exported = true;
          if (service.permission.value)
            item.permission = service.permission.value;

          result.services.push(item);
        }
      }

      const permissions = pkgInfo.requestedPermissions.value;
      if (permissions) {
        for (let i = 0; i < permissions.length; i++) {
          result.permissions.push(permissions[i]);
        }
      }

      resolve(result);
    });
  });
}

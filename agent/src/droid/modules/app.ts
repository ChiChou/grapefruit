import Java from "frida-java-bridge";

export interface ApplicationInfoResult {
  packageName: string;
  processName: string;
  className: string | null;
  taskAffinity: string | null;
  permission: string | null;
  dataDir: string;
  deviceProtectedDataDir: string | null;
  nativeLibraryDir: string;
  publicSourceDir: string;
  sourceDir: string;
  splitPublicSourceDirs: string[] | null;
  splitSourceDirs: string[] | null;
  sharedLibraryFiles: string[] | null;
  uid: number;
  minSdkVersion: number;
  targetSdkVersion: number;
  enabled: boolean;
  flags: number;
  category: number | null;
}

export function info() {
  return new Promise<ApplicationInfoResult>((resolve) => {
    Java.perform(() => {
      const ActivityThread = Java.use("android.app.ActivityThread");
      const context =
        ActivityThread.currentApplication().getApplicationContext();
      const ai = context.getApplicationInfo();

      const sharedLibs = ai.sharedLibraryFiles.value;
      const splitPublic = ai.splitPublicSourceDirs.value;
      const splitSource = ai.splitSourceDirs.value;

      resolve({
        packageName: ai.packageName.value,
        processName: ai.processName.value,
        className: ai.className.value,
        taskAffinity: ai.taskAffinity.value,
        permission: ai.permission.value,
        dataDir: ai.dataDir.value,
        deviceProtectedDataDir: ai.deviceProtectedDataDir?.value || null,
        nativeLibraryDir: ai.nativeLibraryDir.value,
        publicSourceDir: ai.publicSourceDir.value,
        sourceDir: ai.sourceDir.value,
        splitPublicSourceDirs: splitPublic
          ? Array.from({ length: splitPublic.length }, (_, i) => splitPublic[i])
          : null,
        splitSourceDirs: splitSource
          ? Array.from({ length: splitSource.length }, (_, i) => splitSource[i])
          : null,
        sharedLibraryFiles: sharedLibs
          ? Array.from({ length: sharedLibs.length }, (_, i) => sharedLibs[i])
          : null,
        uid: ai.uid.value,
        minSdkVersion: ai.minSdkVersion.value,
        targetSdkVersion: ai.targetSdkVersion.value,
        enabled: ai.enabled.value,
        flags: ai.flags.value,
        category: ai.category?.value ?? null,
      });
    });
  });
}

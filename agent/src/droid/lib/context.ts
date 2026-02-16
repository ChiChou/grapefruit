import Java from "frida-java-bridge";

export function getContext(): Java.Wrapper {
  const ActivityThread = Java.use("android.app.ActivityThread");
  return ActivityThread.currentApplication().getApplicationContext();
}

import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  try {
    const SensorManager = Java.use("android.hardware.SensorManager");
    hooks.push(
      hook(
        SensorManager.registerListener.overload(
          "android.hardware.SensorEventListener",
          "android.hardware.Sensor",
          "int",
        ),
        (original, self, args) => {
          let sensorType = "unknown";
          try {
            const sensor = args[1] as Java.Wrapper;
            sensorType = String(sensor.getType());
          } catch {
            /* ignore */
          }
          send(
            privacyMsg(
              "motion_sensors",
              "SensorManager.registerListener",
              "enter",
              `SensorManager.registerListener(type=${sensorType})`,
              bt(),
              { sensorType },
            ),
          );
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* class unavailable */
  }

  return hooks;
}

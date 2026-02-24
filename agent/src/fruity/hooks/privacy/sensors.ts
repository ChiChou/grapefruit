import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "@/common/hooks/privacy.js";

const MOTION_METHODS = [
  "startAccelerometerUpdatesToQueue:withHandler:",
  "startGyroUpdatesToQueue:withHandler:",
  "startDeviceMotionUpdatesToQueue:withHandler:",
] as const;

export function hook(): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  // CMMotionManager start methods
  try {
    const cls = ObjC.classes.CMMotionManager;
    if (cls) {
      for (const name of MOTION_METHODS) {
        try {
          const m = cls[`- ${name}`];
          if (m) {
            const symbol = `-[CMMotionManager ${name}]`;
            const short = name.split("Updates")[0]!.replace("start", "");
            hooks.push(
              Interceptor.attach(m.implementation, {
                onEnter() {
                  send(privacyMsg("motion_sensors", symbol, "enter",
                    `CMMotionManager.start${short}Updates()`, bt(this.context),
                    { sensorType: short.toLowerCase() }));
                },
              }),
            );
          }
        } catch { /* method unavailable */ }
      }
    }
  } catch { /* class unavailable */ }

  // CMPedometer startPedometerUpdatesFromDate:withHandler:
  try {
    const cls = ObjC.classes.CMPedometer;
    if (cls) {
      const m = cls["- startPedometerUpdatesFromDate:withHandler:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("motion_sensors",
                "-[CMPedometer startPedometerUpdatesFromDate:withHandler:]",
                "enter",
                "CMPedometer.startPedometerUpdates()", bt(this.context),
                { sensorType: "pedometer" }));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  return hooks;
}

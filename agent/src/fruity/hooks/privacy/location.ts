import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "./types.js";

const METHODS = [
  "startUpdatingLocation",
  "requestLocation",
  "startMonitoringSignificantLocationChanges",
  "startUpdatingHeading",
  "requestWhenInUseAuthorization",
  "requestAlwaysAuthorization",
] as const;

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  const cls = ObjC.classes.CLLocationManager;
  if (!cls) return hooks;

  for (const name of METHODS) {
    try {
      const m = cls[`- ${name}`];
      if (m) {
        const symbol = `-[CLLocationManager ${name}]`;
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("location", symbol, "enter",
                `CLLocationManager.${name}()`, bt(this.context)));
            },
          }),
        );
      }
    } catch { /* method unavailable */ }
  }

  return hooks;
}

import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  const cls = ObjC.classes.HKHealthStore;
  if (!cls) return hooks;

  // requestAuthorizationToShareTypes:readTypes:completion:
  try {
    const m = cls["- requestAuthorizationToShareTypes:readTypes:completion:"];
    if (m) {
      hooks.push(
        Interceptor.attach(m.implementation, {
          onEnter() {
            send(privacyMsg("health",
              "-[HKHealthStore requestAuthorizationToShareTypes:readTypes:completion:]",
              "enter",
              "HKHealthStore.requestAuthorization()", bt(this.context)));
          },
        }),
      );
    }
  } catch { /* method unavailable */ }

  // executeQuery:
  try {
    const m = cls["- executeQuery:"];
    if (m) {
      hooks.push(
        Interceptor.attach(m.implementation, {
          onEnter() {
            send(privacyMsg("health", "-[HKHealthStore executeQuery:]", "enter",
              "HKHealthStore.executeQuery()", bt(this.context)));
          },
        }),
      );
    }
  } catch { /* method unavailable */ }

  // saveObject:withCompletion:
  try {
    const m = cls["- saveObject:withCompletion:"];
    if (m) {
      hooks.push(
        Interceptor.attach(m.implementation, {
          onEnter() {
            send(privacyMsg("health", "-[HKHealthStore saveObject:withCompletion:]", "enter",
              "HKHealthStore.saveObject()", bt(this.context)));
          },
        }),
      );
    }
  } catch { /* method unavailable */ }

  return hooks;
}

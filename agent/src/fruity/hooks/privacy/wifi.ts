import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "@/common/hooks/privacy.js";

export function hook(): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  // CNCopyCurrentNetworkInfo (C function)
  try {
    const mod = Process.findModuleByName("SystemConfiguration");
    const addr = mod?.findExportByName("CNCopyCurrentNetworkInfo");
    if (addr) {
      hooks.push(
        Interceptor.attach(addr, {
          onEnter() {
            send(privacyMsg("wifi", "CNCopyCurrentNetworkInfo", "enter",
              "CNCopyCurrentNetworkInfo()", bt(this.context)));
          },
        }),
      );
    }
  } catch { /* symbol unavailable */ }

  // NEHotspotNetwork fetchCurrentWithCompletionHandler:
  if (ObjC.available) {
    try {
      const cls = ObjC.classes.NEHotspotNetwork;
      if (cls) {
        const m = cls["+ fetchCurrentWithCompletionHandler:"];
        if (m) {
          hooks.push(
            Interceptor.attach(m.implementation, {
              onEnter() {
                send(privacyMsg("wifi",
                  "+[NEHotspotNetwork fetchCurrentWithCompletionHandler:]",
                  "enter",
                  "NEHotspotNetwork.fetchCurrent()", bt(this.context)));
              },
            }),
          );
        }
      }
    } catch { /* class unavailable */ }
  }

  return hooks;
}

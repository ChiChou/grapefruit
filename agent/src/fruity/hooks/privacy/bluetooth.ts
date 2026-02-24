import ObjC from "frida-objc-bridge";
import { bt } from "@/common/hooks/context.js";
import { privacyMsg } from "@/common/hooks/privacy.js";

export function hook(): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  if (!ObjC.available) return hooks;

  // CBCentralManager scanForPeripheralsWithServices:options:
  try {
    const cls = ObjC.classes.CBCentralManager;
    if (cls) {
      const m = cls["- scanForPeripheralsWithServices:options:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("bluetooth",
                "-[CBCentralManager scanForPeripheralsWithServices:options:]",
                "enter",
                "CBCentralManager.scanForPeripherals()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // CBCentralManager connectPeripheral:options:
  try {
    const cls = ObjC.classes.CBCentralManager;
    if (cls) {
      const m = cls["- connectPeripheral:options:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("bluetooth",
                "-[CBCentralManager connectPeripheral:options:]",
                "enter",
                "CBCentralManager.connectPeripheral()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  // CBPeripheralManager startAdvertising:
  try {
    const cls = ObjC.classes.CBPeripheralManager;
    if (cls) {
      const m = cls["- startAdvertising:"];
      if (m) {
        hooks.push(
          Interceptor.attach(m.implementation, {
            onEnter() {
              send(privacyMsg("bluetooth",
                "-[CBPeripheralManager startAdvertising:]",
                "enter",
                "CBPeripheralManager.startAdvertising()", bt(this.context)));
            },
          }),
        );
      }
    }
  } catch { /* class unavailable */ }

  return hooks;
}

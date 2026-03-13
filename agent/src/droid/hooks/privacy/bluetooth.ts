import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  // BluetoothAdapter.startDiscovery
  try {
    const BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
    hooks.push(
      hook(
        BluetoothAdapter.startDiscovery.overload(),
        (original, self, args) => {
          send(
            privacyMsg(
              "bluetooth",
              "BluetoothAdapter.startDiscovery",
              "enter",
              "BluetoothAdapter.startDiscovery()",
              bt(),
            ),
          );
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* class unavailable */
  }

  // BluetoothAdapter.getBondedDevices
  try {
    const BluetoothAdapter = Java.use("android.bluetooth.BluetoothAdapter");
    hooks.push(
      hook(
        BluetoothAdapter.getBondedDevices.overload(),
        (original, self, args) => {
          send(
            privacyMsg(
              "bluetooth",
              "BluetoothAdapter.getBondedDevices",
              "enter",
              "BluetoothAdapter.getBondedDevices()",
              bt(),
            ),
          );
          return original.call(self, ...args);
        },
      ),
    );
  } catch {
    /* class unavailable */
  }

  // BluetoothLeScanner.startScan
  try {
    const BluetoothLeScanner = Java.use(
      "android.bluetooth.le.BluetoothLeScanner",
    );
    hooks.push(
      hook(
        BluetoothLeScanner.startScan.overload(
          "android.bluetooth.le.ScanCallback",
        ),
        (original, self, args) => {
          send(
            privacyMsg(
              "bluetooth",
              "BluetoothLeScanner.startScan",
              "enter",
              "BluetoothLeScanner.startScan()",
              bt(),
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

import Java from "frida-java-bridge";

import { hook, bt } from "@/common/hooks/java.js";
import { privacyMsg } from "./types.js";

export default function (): InvocationListener[] {
  const hooks: InvocationListener[] = [];

  const WifiManager = Java.use("android.net.wifi.WifiManager");

  // startScan
  try {
    hooks.push(
      hook(WifiManager.startScan.overload(), (original, self, args) => {
        send(
          privacyMsg(
            "wifi",
            "WifiManager.startScan",
            "enter",
            "WifiManager.startScan()",
            bt(),
          ),
        );
        return original.call(self, ...args);
      }),
    );
  } catch {
    /* method unavailable */
  }

  // getScanResults
  try {
    hooks.push(
      hook(WifiManager.getScanResults.overload(), (original, self, args) => {
        send(
          privacyMsg(
            "wifi",
            "WifiManager.getScanResults",
            "enter",
            "WifiManager.getScanResults()",
            bt(),
          ),
        );
        return original.call(self, ...args);
      }),
    );
  } catch {
    /* method unavailable */
  }

  // getConnectionInfo
  try {
    hooks.push(
      hook(WifiManager.getConnectionInfo.overload(), (original, self, args) => {
        send(
          privacyMsg(
            "wifi",
            "WifiManager.getConnectionInfo",
            "enter",
            "WifiManager.getConnectionInfo()",
            bt(),
          ),
        );
        return original.call(self, ...args);
      }),
    );
  } catch {
    /* method unavailable */
  }

  // ConnectivityManager.getActiveNetworkInfo
  try {
    const ConnectivityManager = Java.use("android.net.ConnectivityManager");
    hooks.push(
      hook(
        ConnectivityManager.getActiveNetworkInfo.overload(),
        (original, self, args) => {
          send(
            privacyMsg(
              "wifi",
              "ConnectivityManager.getActiveNetworkInfo",
              "enter",
              "ConnectivityManager.getActiveNetworkInfo()",
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

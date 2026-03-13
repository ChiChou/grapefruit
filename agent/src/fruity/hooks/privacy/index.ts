import ObjC from "frida-objc-bridge";

import hookMicrophone from "./microphone.js";
import hookCamera from "./camera.js";
import hookPhotos from "./photos.js";
import hookLocation from "./location.js";
import hookHealth from "./health.js";
import hookSensors from "./sensors.js";
import hookBluetooth from "./bluetooth.js";
import hookWifi from "./wifi.js";
import hookMisc from "./misc.js";

const hooks: InvocationListener[] = [];
let running = false;

export function start() {
  if (running || !ObjC.available) return;
  running = true;

  const modules = [
    hookMicrophone,
    hookCamera,
    hookPhotos,
    hookLocation,
    hookHealth,
    hookSensors,
    hookBluetooth,
    hookWifi,
    hookMisc,
  ];

  for (const fn of modules) {
    try {
      hooks.push(...fn());
    } catch (e) {
      console.warn("privacy: hook failed:", e);
    }
  }
}

export function stop() {
  if (!running) return;
  running = false;
  for (const hook of hooks) {
    hook.detach();
  }
  hooks.length = 0;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  return ObjC.available;
}

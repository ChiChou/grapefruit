import Java from "frida-java-bridge";

import hookMicrophone from "./microphone.js";
import hookCamera from "./camera.js";
import hookPhotos from "./photos.js";
import hookSensors from "./sensors.js";
import hookBluetooth from "./bluetooth.js";
import hookWifi from "./wifi.js";
import hookLocation from "./location.js";
import hookHealth from "./health.js";
import hookMisc from "./misc.js";

const hooks: InvocationListener[] = [];
let running = false;

export function start() {
  if (running || !available()) return;
  running = true;

  Java.perform(() => {
    const modules = [
      hookMicrophone,
      hookCamera,
      hookPhotos,
      hookSensors,
      hookBluetooth,
      hookWifi,
      hookLocation,
      hookHealth,
      hookMisc,
    ];

    for (const fn of modules) {
      try {
        hooks.push(...fn());
      } catch (e) {
        console.warn(`privacy: ${fn.name} failed:`, e);
      }
    }
  });
}

export function stop() {
  for (const h of hooks) {
    try {
      h.detach();
    } catch {
      /* ignore */
    }
  }
  hooks.length = 0;
  running = false;
}

export function status(): boolean {
  return running;
}

export function available(): boolean {
  return Java.available;
}

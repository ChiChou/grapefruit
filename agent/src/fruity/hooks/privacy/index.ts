import ObjC from "frida-objc-bridge";

import { hook as hookMicrophone } from "./microphone.js";
import { hook as hookCamera } from "./camera.js";
import { hook as hookPhotos } from "./photos.js";
import { hook as hookLocation } from "./location.js";
import { hook as hookHealth } from "./health.js";
import { hook as hookSensors } from "./sensors.js";
import { hook as hookBluetooth } from "./bluetooth.js";
import { hook as hookWifi } from "./wifi.js";
import { hook as hookMisc } from "./misc.js";

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

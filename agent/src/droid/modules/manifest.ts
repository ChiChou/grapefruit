import Java from "frida-java-bridge";

import { readManifestXml } from "../lib/manifest.js";

export function xml() {
  return new Promise<string>((resolve, reject) => {
    Java.perform(() => {
      try {
        resolve(readManifestXml());
      } catch (e) {
        reject(e);
      }
    });
  });
}

import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";

export interface DeviceInfo {
  model: string;
  brand: string;
  manufacturer: string;
  product: string;
  device: string;
  board: string;
  hardware: string;
  display: string;
  fingerprint: string;
  sdk: number;
  release: string;
  codename: string;
  incremental: string;
  security: string;
  abi: string;
}

export function info() {
  return perform(() => {
    const Build = Java.use("android.os.Build");
    const VERSION = Java.use("android.os.Build$VERSION");

    return {
      model: Build.MODEL.value,
      brand: Build.BRAND.value,
      manufacturer: Build.MANUFACTURER.value,
      product: Build.PRODUCT.value,
      device: Build.DEVICE.value,
      board: Build.BOARD.value,
      hardware: Build.HARDWARE.value,
      display: Build.DISPLAY.value,
      fingerprint: Build.FINGERPRINT.value,
      sdk: VERSION.SDK_INT.value,
      release: VERSION.RELEASE.value,
      codename: VERSION.CODENAME.value,
      incremental: VERSION.INCREMENTAL.value,
      security: VERSION.SECURITY_PATCH?.value || "",
      abi: Build.SUPPORTED_ABIS?.value?.[0] || "",
    } as DeviceInfo;
  });
}

export function properties() {
  return perform(() => {
    const SystemProperties = Java.use("android.os.SystemProperties");
    const Runtime = Java.use("java.lang.Runtime");
    const BufferedReader = Java.use("java.io.BufferedReader");
    const InputStreamReader = Java.use("java.io.InputStreamReader");

    const props: Record<string, string> = {};

    try {
      const process = Runtime.getRuntime().exec("getprop");
      const reader = BufferedReader.$new(
        InputStreamReader.$new(process.getInputStream()),
      );

      let line: string | null;
      while ((line = reader.readLine()) !== null) {
        const match = /^\[(.+?)\]: \[(.*)?\]$/.exec(line);
        if (match) {
          props[match[1]] = match[2] || "";
        }
      }
      reader.close();
    } catch (_) {
      // fallback: read known properties
      const known = [
        "ro.build.version.sdk",
        "ro.build.version.release",
        "ro.build.display.id",
        "ro.product.model",
        "ro.product.brand",
        "ro.product.name",
        "ro.hardware",
        "ro.build.fingerprint",
        "ro.secure",
        "ro.debuggable",
        "ro.build.type",
      ];

      for (const key of known) {
        try {
          const val: string = SystemProperties.get(key, "");
          if (val) props[key] = val;
        } catch (_) {
          // skip
        }
      }
    }

    return props;
  });
}

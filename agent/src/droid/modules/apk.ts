import Java from "frida-java-bridge";

import type { ZipEntry, ZipFile } from "@/droid/bridge/wrapper.js";
import { perform } from "@/common/hooks/java.js";
import { getContext } from "@/droid/lib/context.js";
import { drainInputStream } from "@/droid/lib/jbytes.js";

/** [name, size] */
export type ApkEntry = [string, number];

export interface ApkInfo {
  path: string;
  name: string;
}

/**
 * List all APK files (base + splits) for the current application.
 */
export function list(): Promise<ApkInfo[]> {
  return perform(() => {
    const ai = getContext().getApplicationInfo();
    const result: ApkInfo[] = [];

    const sourceDir: string = ai.sourceDir.value;
    result.push({ path: sourceDir, name: "base.apk" });

    const splitDirs = ai.splitSourceDirs.value;
    if (splitDirs) {
      for (let i = 0; i < splitDirs.length; i++) {
        const p: string = splitDirs[i];
        const name = p.split("/").pop() || `split_${i}.apk`;
        result.push({ path: p, name });
      }
    }

    return result;
  });
}

/**
 * List all file entries inside an APK zip (flat list, no directories).
 * The frontend builds the tree from the full path names.
 */
export function entries(apkPath: string): Promise<ApkEntry[]> {
  return perform(() => {
    const ZipFileCls = Java.use("java.util.zip.ZipFile");
    const zip: ZipFile = ZipFileCls.$new(apkPath);

    try {
      const result: ApkEntry[] = [];
      const ZipEntryCls = Java.use("java.util.zip.ZipEntry");
      const it = zip.entries();
      while (it.hasMoreElements()) {
        const entry = Java.cast(it.nextElement(), ZipEntryCls) as ZipEntry;
        const name = entry.getName() as string;
        // Skip directory entries — they carry no data
        if (name.endsWith("/")) continue;
        result.push([name, entry.getSize()]);
      }
      result.sort((a, b) => a[0].localeCompare(b[0]));
      return result;
    } finally {
      zip.close();
    }
  });
}

/**
 * Read a single entry from an APK zip. Returns the raw bytes as an ArrayBuffer.
 */
export function read(apkPath: string, entryName: string): Promise<ArrayBuffer> {
  return perform(() => {
    const ZipFileCls = Java.use("java.util.zip.ZipFile");

    const zip: ZipFile = ZipFileCls.$new(apkPath);
    try {
      const entry = zip.getEntry(entryName);
      if (!entry) throw new Error(`Entry not found: ${entryName}`);

      const stream = zip.getInputStream(entry);
      const data = drainInputStream(stream);
      stream.close();
      return data;
    } finally {
      zip.close();
    }
  });
}

/**
 * Get the uncompressed size of an entry inside an APK zip.
 */
export function size(apkPath: string, entryName: string): Promise<number> {
  return perform(() => {
    const ZipFileCls = Java.use("java.util.zip.ZipFile");
    const zip: ZipFile = ZipFileCls.$new(apkPath);
    try {
      const entry = zip.getEntry(entryName);
      if (!entry) throw new Error(`Entry not found: ${entryName}`);
      return entry.getSize();
    } finally {
      zip.close();
    }
  });
}

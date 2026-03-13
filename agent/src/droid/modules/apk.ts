import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";
import { getContext } from "@/droid/lib/context.js";
import { drainInputStream } from "@/droid/lib/jbytes.js";

export interface ApkEntry {
  name: string;
  dir: boolean;
  size: number | null;
  compressedSize: number | null;
}

export interface ApkInfo {
  path: string;
  name: string;
}

export interface ApkListing {
  apk: string;
  path: string;
  entries: ApkEntry[];
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
 * List entries inside an APK zip at the given internal directory path.
 * `internalPath` should be "" for root, or "lib/arm64-v8a" etc.
 * Returns only direct children (not recursive).
 */
export function ls(apkPath: string, internalPath: string): Promise<ApkListing> {
  return perform(() => {
    const ZipFile = Java.use("java.util.zip.ZipFile");
    const zip = ZipFile.$new(apkPath);

    try {
      const prefix = internalPath ? internalPath.replace(/\/$/, "") + "/" : "";
      const prefixLen = prefix.length;
      const dirs = new Set<string>();
      const files: ApkEntry[] = [];

      const ZipEntry = Java.use("java.util.zip.ZipEntry");
      const entries = zip.entries();
      while (entries.hasMoreElements()) {
        const entry = Java.cast(entries.nextElement(), ZipEntry);
        const fullName: string = entry.getName() as string;

        // Skip if not under our prefix
        if (prefix && !fullName.startsWith(prefix)) continue;
        // Skip the prefix directory entry itself
        if (fullName === prefix) continue;

        const rest = fullName.slice(prefixLen);
        const slashIdx = rest.indexOf("/");

        if (slashIdx === -1) {
          // Direct file child
          files.push({
            name: rest,
            dir: false,
            size: Number(entry.getSize()),
            compressedSize: Number(entry.getCompressedSize()),
          });
        } else {
          // Subdirectory - extract the first component
          const dirName = rest.slice(0, slashIdx);
          if (!dirs.has(dirName)) {
            dirs.add(dirName);
            files.push({
              name: dirName,
              dir: true,
              size: null,
              compressedSize: null,
            });
          }
        }
      }

      // Sort: directories first, then alphabetically
      files.sort((a, b) => {
        if (a.dir !== b.dir) return a.dir ? -1 : 1;
        return a.name.localeCompare(b.name);
      });

      return { apk: apkPath, path: internalPath, entries: files } as ApkListing;
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
    const ZipFile = Java.use("java.util.zip.ZipFile");

    const zip = ZipFile.$new(apkPath);
    try {
      const entry = zip.getEntry(entryName);
      if (!entry) throw new Error(`Entry not found: ${entryName}`);

      const inputStream = zip.getInputStream(entry);
      const data = drainInputStream(inputStream);
      inputStream.close();
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
    const ZipFile = Java.use("java.util.zip.ZipFile");
    const zip = ZipFile.$new(apkPath);
    try {
      const entry = zip.getEntry(entryName);
      if (!entry) throw new Error(`Entry not found: ${entryName}`);
      return Number(entry.getSize());
    } finally {
      zip.close();
    }
  });
}

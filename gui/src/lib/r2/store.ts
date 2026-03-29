/**
 * IndexedDB cache for the radare2 WASM binary.
 * Keyed by version string so upgrades automatically invalidate the cache.
 */

const DB_NAME = "r2-wasm-cache";
const DB_VERSION = 1;
const STORE = "blobs";

interface CacheEntry {
  version: string;
  data: ArrayBuffer;
  storedAt: number;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "version" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function get(version: string): Promise<ArrayBuffer | null> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(version);
    req.onsuccess = () => {
      const entry = req.result as CacheEntry | undefined;
      resolve(entry?.data ?? null);
    };
    req.onerror = () => reject(req.error);
  });
}

export async function put(version: string, data: ArrayBuffer): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put({ version, data, storedAt: Date.now() } satisfies CacheEntry);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

/**
 * IndexedDB storage for files opened in the radare2 decompiler.
 */

const DB_NAME = "r2-decompiler";
const DB_VERSION = 1;
const STORE = "files";

export interface StoredFile {
  id: string;
  name: string;
  data: ArrayBuffer;
  addedAt: number;
  source: string;
}

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "id" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

export async function list(): Promise<Omit<StoredFile, "data">[]> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => {
      resolve(
        (req.result as StoredFile[]).map(({ id, name, addedAt, source }) => ({
          id, name, addedAt, source,
        })),
      );
    };
    req.onerror = () => reject(req.error);
  });
}

export async function get(id: string): Promise<StoredFile | undefined> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).get(id);
    req.onsuccess = () => resolve(req.result ?? undefined);
    req.onerror = () => reject(req.error);
  });
}

export async function put(file: StoredFile): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).put(file);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function remove(id: string): Promise<void> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readwrite");
    tx.objectStore(STORE).delete(id);
    tx.oncomplete = () => resolve();
    tx.onerror = () => reject(tx.error);
  });
}

export async function usage(): Promise<number> {
  const db = await open();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(STORE, "readonly");
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => {
      let total = 0;
      for (const entry of req.result as StoredFile[]) total += entry.data.byteLength;
      resolve(total);
    };
    req.onerror = () => reject(req.error);
  });
}

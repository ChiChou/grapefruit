import Java from "frida-java-bridge";

export class RefTracker {
  private trackers = new Map<string, Java.Wrapper>();
  private WeakReference = Java.use("java.lang.ref.WeakReference");

  put(handle: string, instance: Java.Wrapper) {
    this.trackers.set(handle, this.WeakReference.$new(instance));
  }

  get(handle: string): Java.Wrapper {
    const weakRef = this.trackers.get(handle);

    if (!weakRef) {
      throw new Error(`Handle (${handle}) is not tracked.`);
    }

    const instance = weakRef.get();
    if (instance === null) {
      this.trackers.delete(handle); // Clean up dead reference
      throw new Error(`Instance (${handle}) has been garbage collected`);
    }

    return Java.cast(instance, Java.use(instance.$className));
  }

  has(handle: string): boolean {
    const weakRef = this.trackers.get(handle);
    if (!weakRef) return false;

    const isAlive = weakRef.get() !== null;
    if (!isAlive) {
      this.trackers.delete(handle); // Clean up dead reference
    }

    return isAlive;
  }
}

let singleton: RefTracker | null = null;

export function getTracker(): RefTracker {
  if (!singleton) singleton = new RefTracker();
  return singleton;
}

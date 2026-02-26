import Java from "frida-java-bridge";

export class Registry {
  private map: Java.Wrapper;

  constructor() {
    const WeakHashMap = Java.use("java.util.WeakHashMap");
    const Collections = Java.use("java.util.Collections");

    this.map = Collections.synchronizedMap(WeakHashMap.$new());
  }

  public set(obj: Java.Wrapper, value: Java.Wrapper): void {
    if (obj !== null) this.map.put(obj, value);
  }

  public get(obj: Java.Wrapper): Java.Wrapper | null {
    return obj !== null ? this.map.get(obj) : null;
  }
}

export const bodyRegistry = new Registry();
export const streamRegistry = new Registry();

export function readJavaByteArray(
  array: Java.Wrapper,
  offset: number,
  length: number,
): ArrayBuffer | null {
  if (length <= 0) return null;
  const env = Java.vm.getEnv();
  const handle = array.$handle ?? array.$h;
  const ptr = env.getByteArrayElements(handle);
  try {
    return ptr.add(offset).readByteArray(length)!;
  } finally {
    env.releaseByteArrayElements(handle, ptr);
  }
}

function readJavaCharArray(
  array: Java.Wrapper,
  offset: number,
  length: number,
): ArrayBuffer | null {
  if (length <= 0) return null;
  const env = Java.vm.getEnv();
  const handle = array.$handle ?? array.$h;
  const ptr = env.getCharArrayElements(handle);
  try {
    return ptr.add(offset * 2).readByteArray(length * 2)!;
  } finally {
    env.releaseCharArrayElements(handle, ptr);
  }
}

export function byteArrayToBuffer(
  arr: Java.Wrapper,
): { data: ArrayBuffer; length: number } | null {
  if (arr === null) return null;
  const handle = arr.$handle ?? arr.$h;
  if (handle) {
    const env = Java.vm.getEnv();
    const len = env.getArrayLength(handle);
    const data = readJavaByteArray(arr, 0, len);
    return data ? { data, length: len } : null;
  }
  if (typeof arr.length === "number" && arr.length > 0) {
    const len = arr.length;
    const buf = new ArrayBuffer(len);
    const view = new Uint8Array(buf);
    for (let i = 0; i < len; i++) view[i] = arr[i] & 0xff;
    return { data: buf, length: len };
  }
  return null;
}

const hookedInputStreamClasses = new Set<string>();
const hookedReaderClasses = new Set<string>();

function hookInputStreamClass(className: string): void {
  try {
    const Cls = Java.use(className);

    const readMethod = Cls.read.overload("[B", "int", "int");
    readMethod.implementation = function (
      this: Java.Wrapper,
      buf: Java.Wrapper,
      off: number,
      len: number,
    ) {
      const n: number = readMethod.call(this, buf, off, len);
      const jrid = streamRegistry.get(this);
      if (jrid !== null && n > 0) {
        const rid = jrid.toString();
        const data = readJavaByteArray(buf, off, n);
        if (data) {
          send(
            {
              subject: "http",
              type: "responseBodyChunk",
              requestId: rid,
              timestamp: Date.now(),
              bytesRead: n,
            },
            data,
          );
        }
      }
      return n;
    };

    const closeMethod = Cls.close.overload();
    closeMethod.implementation = function (this: Java.Wrapper) {
      const jrid = streamRegistry.get(this);
      if (jrid !== null) {
        send({
          subject: "http",
          type: "responseBodyEnd",
          requestId: jrid.toString(),
          timestamp: Date.now(),
        });
      }
      return closeMethod.call(this);
    };

  } catch {
  }
}

function hookReaderClass(className: string): void {
  try {
    const Cls = Java.use(className);

    const readMethod = Cls.read.overload("[C", "int", "int");
    readMethod.implementation = function (
      this: Java.Wrapper,
      cbuf: Java.Wrapper,
      off: number,
      len: number,
    ) {
      const n: number = readMethod.call(this, cbuf, off, len);
      const jrid = streamRegistry.get(this);
      if (jrid !== null && n > 0) {
        const rid = jrid.toString();
        const data = readJavaCharArray(cbuf, off, n);
        if (data) {
          send(
            {
              subject: "http",
              type: "responseBodyChunk",
              requestId: rid,
              timestamp: Date.now(),
              charsRead: n,
              encoding: "utf-16",
            },
            data,
          );
        }
      }
      return n;
    };

    const closeMethod = Cls.close.overload();
    closeMethod.implementation = function (this: Java.Wrapper) {
      const jrid = streamRegistry.get(this);
      if (jrid !== null) {
        send({
          subject: "http",
          type: "responseBodyEnd",
          requestId: jrid.toString(),
          timestamp: Date.now(),
        });
      }
      return closeMethod.call(this);
    };

  } catch {
  }
}

export function tagStream(stream: Java.Wrapper, rid: string): void {
  streamRegistry.set(stream, Java.use("java.lang.String").$new(rid));
  const cls = stream.$className;
  if (!hookedInputStreamClasses.has(cls)) {
    hookedInputStreamClasses.add(cls);
    hookInputStreamClass(cls);
  }
}

export function tagReader(reader: Java.Wrapper, rid: string): void {
  streamRegistry.set(reader, Java.use("java.lang.String").$new(rid));
  const cls = reader.$className;
  if (!hookedReaderClasses.has(cls)) {
    hookedReaderClasses.add(cls);
    hookReaderClass(cls);
  }
}

export function captureBacktrace(): string[] {
  try {
    const { frames } = Java.backtrace();
    return frames.map(
      (f) => `${f.className}.${f.methodName}(${f.fileName}:${f.lineNumber})`,
    );
  } catch {
    return [];
  }
}

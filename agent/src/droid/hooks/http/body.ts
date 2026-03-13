import Java from "frida-java-bridge";

import {
  readJavaByteArray,
  readJavaCharArray,
  byteArrayToBuffer,
} from "@/droid/lib/jbytes.js";

export { readJavaByteArray, byteArrayToBuffer };

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

import Java from "frida-java-bridge";

import type {
  ByteArrayOutputStream,
  InputStream,
  JavaHandle,
} from "@/droid/bridge/wrapper.js";

/**
 * Fast Java byte[] → ArrayBuffer copy using JNI GetByteArrayElements.
 * Falls back to element-by-element copy for plain JS arrays.
 */
export function readJavaByteArray(
  array: Java.Wrapper,
  offset: number,
  length: number,
): ArrayBuffer | null {
  if (length <= 0) return null;
  const env = Java.vm.getEnv();
  const handle = (array as JavaHandle).$h;
  const ptr = env.getByteArrayElements(handle);
  try {
    return ptr.add(offset).readByteArray(length)!;
  } finally {
    env.releaseByteArrayElements(handle, ptr);
  }
}

/**
 * Fast Java char[] → ArrayBuffer copy using JNI GetCharArrayElements.
 * Returns UTF-16LE bytes (2 bytes per char).
 */
export function readJavaCharArray(
  array: Java.Wrapper,
  offset: number,
  length: number,
): ArrayBuffer | null {
  if (length <= 0) return null;
  const env = Java.vm.getEnv();
  const handle = (array as JavaHandle).$h;
  const ptr = env.getCharArrayElements(handle);
  try {
    return ptr.add(offset * 2).readByteArray(length * 2)!;
  } finally {
    env.releaseCharArrayElements(handle, ptr);
  }
}

/**
 * Convert a Java byte[] to an ArrayBuffer.
 * Tries the fast JNI path first, falls back to element-wise copy.
 */
export function byteArrayToBuffer(
  arr: Java.Wrapper,
): { data: ArrayBuffer; length: number } | null {
  if (arr === null) return null;
  const handle = (arr as JavaHandle).$h;
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

/**
 * Allocate a reusable Java byte[] buffer.
 */
export function allocByteBuffer(size: number) {
  return Java.array("byte", new Array(size).fill(0));
}

/**
 * Read from a Java InputStream into an ArrayBuffer using the fast JNI path.
 * Returns the full contents.
 */
export function drainInputStream(
  inputStream: InputStream,
  bufferSize = 8192,
): ArrayBuffer {
  const BAOS = Java.use("java.io.ByteArrayOutputStream");
  const baos: ByteArrayOutputStream = BAOS.$new();
  // Java.array() returns a Java Wrapper at runtime despite any[] typedef
  const buffer = allocByteBuffer(bufferSize) as unknown as Java.Wrapper;
  let len: number;
  while ((len = inputStream.read(buffer)) !== -1) {
    baos.write(buffer, 0, len);
  }
  const result = byteArrayToBuffer(baos.toByteArray());
  return result ? result.data : new ArrayBuffer(0);
}

/**
 * Read `len` bytes from a Java byte[] buffer via JNI into a Uint8Array.
 * Used for streaming scenarios where you read chunks from an InputStream
 * into a reusable Java byte[] buffer.
 */
export function readChunkFromBuffer(
  buffer: Java.Wrapper,
  len: number,
): Uint8Array {
  const ab = readJavaByteArray(buffer, 0, len);
  return ab ? new Uint8Array(ab) : new Uint8Array(0);
}

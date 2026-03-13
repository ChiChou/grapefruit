import type Java from "frida-java-bridge";

/**
 * frida-java-bridge Wrapper with the internal $h handle exposed.
 * $h is the actual JNI global ref field (not typed in @types).
 */
export type JavaHandle = Java.Wrapper & { $h: NativePointer };

export type Static<T extends Java.Wrapper = Java.Wrapper> = Java.Wrapper & {
  $new(...args: unknown[]): T;
  $alloc(): T;
};

export interface InputStream extends Java.Wrapper {
  read(buffer: Java.Wrapper): number;
  close(): void;
}

export interface OutputStream extends Java.Wrapper {
  write(buffer: Java.Wrapper, offset: number, length: number): void;
  close(): void;
}

export interface ByteArrayOutputStream extends OutputStream {
  toByteArray(): Java.Wrapper;
}

export interface ZipFile extends Java.Wrapper {
  entries(): Enumeration;
  getEntry(name: string): ZipEntry | null;
  getInputStream(entry: ZipEntry): InputStream;
  close(): void;
}

export interface ZipEntry extends Java.Wrapper {
  getName(): string;
  getSize(): number;
  getCompressedSize(): number;
  isDirectory(): boolean;
}

export interface Enumeration extends Java.Wrapper {
  hasMoreElements(): boolean;
  nextElement(): Java.Wrapper;
}

export interface JavaFile extends Java.Wrapper {
  exists(): boolean;
  isDirectory(): boolean;
  isFile(): boolean;
  canWrite(): boolean;
  delete(): boolean;
  mkdirs(): boolean;
  getName(): string;
  getParent(): string;
  getAbsolutePath(): string;
  getCanonicalPath(): string;
  getParentFile(): JavaFile | null;
  listFiles(): JavaFile[] | null;
  length(): number;
  lastModified(): number;
}

/** Java.vm with the internal handle exposed (not typed upstream). */
export type JavaVM = Java.VM & { handle: NativePointer };

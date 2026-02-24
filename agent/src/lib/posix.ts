import { getGlobalExport } from "@/lib/polyfill.js";

interface PosixApi {
  open: NativeFunction<number, [NativePointer, number, number]>;
  read: NativeFunction<number, [number, NativePointer, number]>;
  close: NativeFunction<number, [number]>;
  lseek: NativeFunction<Int64, [number, Int64 | number, number]>;
  rename: NativeFunction<number, [NativePointer, NativePointer]>;
  unlink: NativeFunction<number, [NativePointer]>;
  access: NativeFunction<number, [NativePointer, number]>;
  mkdir: NativeFunction<number, [NativePointer, number]>;
}

let cachedApi: PosixApi;

function getApi(): PosixApi {
  if (cachedApi) return cachedApi;
  cachedApi = {
    open: new NativeFunction(getGlobalExport("open"), "int", [
      "pointer",
      "int",
      "int",
    ]),
    read: new NativeFunction(getGlobalExport("read"), "int", [
      "int",
      "pointer",
      "int",
    ]),
    close: new NativeFunction(getGlobalExport("close"), "int", ["int"]),
    lseek: new NativeFunction(getGlobalExport("lseek"), "int64", [
      "int",
      "int64",
      "int",
    ]),
    rename: new NativeFunction(getGlobalExport("rename"), "int", [
      "pointer",
      "pointer",
    ]),
    unlink: new NativeFunction(getGlobalExport("unlink"), "int", ["pointer"]),
    access: new NativeFunction(getGlobalExport("access"), "int", [
      "pointer",
      "int",
    ]),
    mkdir: new NativeFunction(getGlobalExport("mkdir"), "int", [
      "pointer",
      "int",
    ]),
  };
  return cachedApi;
}

const O_RDONLY = 0;
const SEEK_END = 2;
const SEEK_SET = 0;
const W_OK = 2;

export function readFile(filePath: string, limit?: number): ArrayBuffer | null {
  if (limit !== undefined && limit <= 0) return new ArrayBuffer(0);

  const api = getApi();
  const pathBuf = Memory.allocUtf8String(filePath);
  const fd = api.open(pathBuf, O_RDONLY, 0) as number;
  if (fd < 0) return null;

  const size = Number(api.lseek(fd, 0, SEEK_END));
  const toRead = limit ? Math.min(size, limit) : size;
  if (toRead <= 0) {
    api.close(fd);
    return new ArrayBuffer(0);
  }

  api.lseek(fd, 0, SEEK_SET);
  const buf = Memory.alloc(toRead);
  let total = 0;
  while (total < toRead) {
    const n = api.read(fd, buf.add(total), toRead - total) as number;
    if (n <= 0) break;
    total += n;
  }

  api.close(fd);
  return buf.readByteArray(total);
}

export function rename(src: string, dst: string): boolean {
  const api = getApi();
  const srcBuf = Memory.allocUtf8String(src);
  const dstBuf = Memory.allocUtf8String(dst);
  const result = api.rename(srcBuf, dstBuf) as number;
  if (result !== 0) throw new Error(`rename failed: ${src} -> ${dst}`);
  return true;
}

export function unlink(path: string): void {
  const api = getApi();
  api.unlink(Memory.allocUtf8String(path));
}

export function isWritable(path: string): boolean {
  const api = getApi();
  const pathBuf = Memory.allocUtf8String(path);
  return (api.access(pathBuf, W_OK) as number) === 0;
}

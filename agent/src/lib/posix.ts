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

export const O_RDONLY = 0;
export const SEEK_END = 2;
export const SEEK_SET = 0;
export const W_OK = 2;

export function open(path: string, flags: number, mode: number): number {
  return getApi().open(Memory.allocUtf8String(path), flags, mode) as number;
}

export function read(fd: number, buf: NativePointer, count: number): number {
  return getApi().read(fd, buf, count) as number;
}

export function close(fd: number): number {
  return getApi().close(fd) as number;
}

export function lseek(fd: number, offset: number, whence: number): number {
  return Number(getApi().lseek(fd, offset, whence));
}

export function rename(src: string, dst: string): number {
  return getApi().rename(
    Memory.allocUtf8String(src),
    Memory.allocUtf8String(dst),
  ) as number;
}

export function unlink(path: string): number {
  return getApi().unlink(Memory.allocUtf8String(path)) as number;
}

export function access(path: string, mode: number): number {
  return getApi().access(Memory.allocUtf8String(path), mode) as number;
}

export function mkdir(path: string, mode: number): number {
  return getApi().mkdir(Memory.allocUtf8String(path), mode) as number;
}

import * as posix from "@/lib/posix.js";

export function size(path: string): number {
  const fd = posix.open(path, posix.O_RDONLY, 0);
  if (fd < 0) return 0;
  const n = posix.lseek(fd, 0, posix.SEEK_END);
  posix.close(fd);
  return n;
}

export function readFile(path: string, limit?: number): ArrayBuffer | null {
  if (limit !== undefined && limit <= 0) return new ArrayBuffer(0);

  const fd = posix.open(path, posix.O_RDONLY, 0);
  if (fd < 0) return null;

  const total = posix.lseek(fd, 0, posix.SEEK_END);
  const toRead = limit ? Math.min(total, limit) : total;
  if (toRead <= 0) {
    posix.close(fd);
    return new ArrayBuffer(0);
  }

  posix.lseek(fd, 0, posix.SEEK_SET);
  const buf = Memory.alloc(toRead);
  let got = 0;
  while (got < toRead) {
    const n = posix.read(fd, buf.add(got), toRead - got);
    if (n <= 0) break;
    got += n;
  }

  posix.close(fd);
  return buf.readByteArray(got);
}

export function readRange(
  path: string,
  offset: number,
  length: number,
): ArrayBuffer | null {
  const fd = posix.open(path, posix.O_RDONLY, 0);
  if (fd < 0) return null;

  posix.lseek(fd, offset, posix.SEEK_SET);
  const buf = Memory.alloc(length);
  let got = 0;
  while (got < length) {
    const n = posix.read(fd, buf.add(got), length - got);
    if (n <= 0) break;
    got += n;
  }

  posix.close(fd);
  if (got === 0) return new ArrayBuffer(0);
  return buf.readByteArray(got);
}

export function rename(src: string, dst: string): boolean {
  const result = posix.rename(src, dst);
  if (result !== 0) throw new Error(`rename failed: ${src} -> ${dst}`);
  return true;
}

export function unlink(path: string): void {
  posix.unlink(path);
}

export function isWritable(path: string): boolean {
  return posix.access(path, posix.W_OK) === 0;
}

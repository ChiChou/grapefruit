import Java from "frida-java-bridge";

import type { JavaFile } from "@/droid/bridge/wrapper.js";
import { perform } from "@/common/hooks/java.js";
import { getContext } from "@/droid/lib/context.js";
import { allocByteBuffer } from "@/droid/lib/jbytes.js";
import * as posix from "@/lib/posix.js";
import type { Roots } from "@/common/fs.js";

export interface MetaData {
  name: string;
  dir: boolean;
  protection: string | null;
  size: number | null;
  alias: boolean;
  created: Date;
  symlink: boolean;
}

export interface DirectoryListing {
  cwd: string;
  writable: boolean;
  list: MetaData[];
}

export interface FileAttributes {
  created: Date;
  gid: number;
  group: string;
  uid: number;
  owner: string;
  perm: number;
  protection: string;
  size: number;
  type: string;
}

let homeDir: string;
let bundleDir: string;

function initPaths() {
  if (homeDir) return;
  Java.perform(() => {
    const ctx = getContext();
    const filesDir: JavaFile = ctx.getFilesDir();
    homeDir = filesDir.getParentFile()!.getAbsolutePath();
    const File = Java.use("java.io.File");
    const codeFile: JavaFile = File.$new(ctx.getPackageCodePath() as string);
    bundleDir = codeFile.getParent();
  });
}

export function roots(): Roots {
  initPaths();
  return { home: homeDir, bundle: bundleDir };
}

export function ls(path: string) {
  return perform(() => {
    const File = Java.use("java.io.File");
    const cwd = path;
    const dir: JavaFile = File.$new(cwd);

    if (!dir.exists()) throw new Error(`Path does not exist: ${cwd}`);
    if (!dir.isDirectory()) throw new Error(`Not a directory: ${cwd}`);

    const writable = dir.canWrite();
    const files = dir.listFiles();
    const list: MetaData[] = [];

    if (files) {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const absPath = f.getAbsolutePath();
        const canonPath = f.getCanonicalPath();

        list.push({
          name: f.getName(),
          dir: f.isDirectory(),
          protection: null,
          size: f.isFile() ? f.length() : null,
          alias: false,
          created: new Date(f.lastModified()),
          symlink: absPath !== canonPath,
        });
      }
    }

    return { cwd, writable, list } as DirectoryListing;
  });
}

export function rm(path: string) {
  return perform(() => {
    const File = Java.use("java.io.File");
    const target: JavaFile = File.$new(path);
    if (!target.exists()) throw new Error(`Path does not exist: ${path}`);

    function deleteRecursive(f: JavaFile): boolean {
      if (f.isDirectory()) {
        const children = f.listFiles();
        if (children) {
          for (let i = 0; i < children.length; i++) {
            deleteRecursive(children[i]);
          }
        }
      }
      return f.delete();
    }

    return deleteRecursive(target);
  });
}

export function cp(src: string, dst: string) {
  return perform(() => {
    const File = Java.use("java.io.File");
    const FileInputStream = Java.use("java.io.FileInputStream");
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const srcFile: JavaFile = File.$new(src);
    const dstFile: JavaFile = File.$new(dst);

    function copyRecursive(s: JavaFile, d: JavaFile) {
      if (s.isDirectory()) {
        d.mkdirs();
        const children = s.listFiles();
        if (children) {
          for (let i = 0; i < children.length; i++) {
            copyRecursive(children[i], File.$new(d, children[i].getName()));
          }
        }
      } else {
        const parent = d.getParentFile();
        if (parent && !parent.exists()) parent.mkdirs();

        const fis = FileInputStream.$new(s);
        const fos = FileOutputStream.$new(d);
        const buf = allocByteBuffer(8192);
        let n: number;
        while ((n = fis.read(buf)) !== -1) {
          fos.write(buf, 0, n);
        }
        fis.close();
        fos.close();
      }
    }

    copyRecursive(srcFile, dstFile);
    return true;
  });
}

export function mv(src: string, dst: string) {
  return posix.rename(src, dst);
}

export function mkdirp(path: string) {
  return perform(() => {
    const File = Java.use("java.io.File");
    const dir: JavaFile = File.$new(path);
    return dir.mkdirs();
  });
}

export function attrs(path: string) {
  return perform(() => {
    const Os = Java.use("android.system.Os");
    const stat = Os.lstat(path);

    const mode = stat.st_mode.value as number;
    const fmt = mode & 0o170000;

    let type = "unknown";
    if (fmt === 0o100000) type = "regular";
    else if (fmt === 0o040000) type = "directory";
    else if (fmt === 0o120000) type = "symlink";
    else if (fmt === 0o060000) type = "block";
    else if (fmt === 0o020000) type = "character";
    else if (fmt === 0o010000) type = "fifo";
    else if (fmt === 0o140000) type = "socket";

    return {
      created: new Date((stat.st_ctime.value as number) * 1000),
      gid: stat.st_gid.value as number,
      group: "",
      uid: stat.st_uid.value as number,
      owner: "",
      perm: mode & 0o7777,
      protection: "",
      size: Number(stat.st_size.value),
      type,
    } as FileAttributes;
  });
}

export function text(path: string) {
  return perform(() => {
    const BufferedReader = Java.use("java.io.BufferedReader");
    const FileReader = Java.use("java.io.FileReader");
    const StringBuilder = Java.use("java.lang.StringBuilder");
    const sb = StringBuilder.$new();
    const reader = BufferedReader.$new(FileReader.$new(path));
    let line: string | null;
    while ((line = reader.readLine() as string | null) !== null) {
      sb.append(line).append("\n");
    }
    reader.close();
    return sb.toString() as string;
  });
}

export function data(path: string) {
  return posix.readFile(path);
}

export function preview(path: string) {
  return posix.readFile(path, 1024 * 1024);
}

export function access(path: string) {
  return posix.isWritable(path);
}

export function saveText(path: string, content: string) {
  return perform(() => {
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const fos = FileOutputStream.$new(path);
    const bytes = Java.use("java.lang.String").$new(content).getBytes("UTF-8");
    fos.write(bytes);
    fos.close();
    return true;
  });
}

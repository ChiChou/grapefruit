import { getGlobalExport } from "@/lib/polyfill.js";
import Java from "frida-java-bridge";

import { perform } from "@/common/hooks/java.js";
import { getContext } from "@/droid/lib/context.js";

export interface MetaData {
  name: string;
  dir: boolean;
  protection: string | null;
  size: number | null;
  alias: boolean;
  created: Date;
  symlink: boolean;
  writable: boolean;
}

export interface DirectoryListing {
  cwd: string;
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

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function expandPath(path: string): string {
  if (path.startsWith("~/") || path === "~") {
    const dataDir = getContext()
      .getFilesDir()
      .getParentFile()
      .getAbsolutePath() as string;
    return path === "~" ? dataDir : dataDir + path.substring(1);
  }

  if (path.startsWith("!/") || path === "!") {
    const File = Java.use("java.io.File");
    const apkDir = File.$new(
      getContext().getPackageCodePath() as string,
    ).getParent() as string;
    return path === "!" ? apkDir : apkDir + path.substring(1);
  }

  if (path.startsWith("/")) return path;

  throw new Error(`Cannot expand path: ${path}`);
}

const open = new NativeFunction(getGlobalExport("open"), "int", [
  "pointer",
  "int",
  "int",
]);
const read = new NativeFunction(getGlobalExport("read"), "int", [
  "int",
  "pointer",
  "int",
]);
const close = new NativeFunction(getGlobalExport("close"), "int", ["int"]);
const lseek = new NativeFunction(getGlobalExport("lseek"), "int64", [
  "int",
  "int64",
  "int",
]);

function readBytes(filePath: string, limit?: number): ArrayBuffer | null {
  const pathBuf = Memory.allocUtf8String(filePath);
  const fd = open(pathBuf, 0 /* O_RDONLY */, 0) as number;
  if (fd < 0) return null;

  const size = Number(lseek(fd, 0, 2 /* SEEK_END */));
  lseek(fd, 0, 0 /* SEEK_SET */);

  const toRead = limit ? Math.min(size, limit) : size;
  if (toRead <= 0) {
    close(fd);
    return new ArrayBuffer(0);
  }

  const buf = Memory.alloc(toRead);
  let total = 0;
  while (total < toRead) {
    const n = read(fd, buf.add(total), toRead - total) as number;
    if (n <= 0) break;
    total += n;
  }

  close(fd);
  return buf.readByteArray(total);
}

// ---------------------------------------------------------------------------
// exports
// ---------------------------------------------------------------------------

export function ls(path: string) {
  return perform(() => {
    const File = Java.use("java.io.File");
    const cwd = expandPath(path);
    const dir = File.$new(cwd);

    if (!dir.exists()) throw new Error(`Path does not exist: ${cwd}`);
    if (!dir.isDirectory()) throw new Error(`Not a directory: ${cwd}`);

    const files = dir.listFiles();
    const list: MetaData[] = [];

    if (files) {
      for (let i = 0; i < files.length; i++) {
        const f = files[i];
        const absPath = f.getAbsolutePath() as string;
        const canonPath = f.getCanonicalPath() as string;

        list.push({
          name: f.getName() as string,
          dir: !!f.isDirectory(),
          protection: null,
          size: f.isFile() ? Number(f.length()) : null,
          alias: false,
          created: new Date(Number(f.lastModified())),
          symlink: absPath !== canonPath,
          writable: !!f.canWrite(),
        });
      }
    }

    return { cwd, list } as DirectoryListing;
  });
}

export function rm(path: string) {
  return perform(() => {
    const File = Java.use("java.io.File");
    const target = File.$new(expandPath(path));
    if (!target.exists()) throw new Error(`Path does not exist: ${path}`);

    function deleteRecursive(f: Java.Wrapper): boolean {
      if (f.isDirectory()) {
        const children = f.listFiles();
        if (children) {
          for (let i = 0; i < children.length; i++) {
            deleteRecursive(children[i]);
          }
        }
      }
      return !!f.delete();
    }

    return deleteRecursive(target);
  });
}

export function cp(src: string, dst: string) {
  return perform(() => {
    const File = Java.use("java.io.File");
    const FileInputStream = Java.use("java.io.FileInputStream");
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const srcFile = File.$new(expandPath(src));
    const dstFile = File.$new(expandPath(dst));

    function copyRecursive(s: Java.Wrapper, d: Java.Wrapper) {
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
        const buf = Java.array("byte", new Array(8192).fill(0));
        let n: number;
        while ((n = fis.read(buf) as number) !== -1) {
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
  return perform(() => {
    const File = Java.use("java.io.File");
    const result = File.$new(expandPath(src)).renameTo(
      File.$new(expandPath(dst)),
    );
    return !!result;
  });
}

export function attrs(path: string) {
  return perform(() => {
    const Os = Java.use("android.system.Os");
    const expandedPath = expandPath(path);
    const stat = Os.lstat(expandedPath);

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
    const expandedPath = expandPath(path);
    const Paths = Java.use("java.nio.file.Paths");
    const NioFiles = Java.use("java.nio.file.Files");
    const JString = Java.use("java.lang.String");

    const nioPath = Paths.get(
      expandedPath,
      Java.array("java.lang.String", []),
    );
    const bytes = NioFiles.readAllBytes(nioPath);
    return JString.$new(bytes, "UTF-8").toString() as string;
  });
}

export function data(path: string) {
  return perform(() => readBytes(expandPath(path)));
}

export function preview(path: string) {
  return perform(() => readBytes(expandPath(path), 1024 * 1024));
}

export function saveText(path: string, content: string) {
  return perform(() => {
    const expandedPath = expandPath(path);
    const FileOutputStream = Java.use("java.io.FileOutputStream");
    const fos = FileOutputStream.$new(expandedPath);
    const bytes = Java.use("java.lang.String")
      .$new(content)
      .getBytes("UTF-8");
    fos.write(bytes);
    fos.close();
    return true;
  });
}

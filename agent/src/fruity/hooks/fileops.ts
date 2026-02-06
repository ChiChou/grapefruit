import { BaseMessage, bt } from "@/common/hooks/context.js";

export interface Message extends BaseMessage {
  subject: "hook";
  category: "fileops";
  op: "open" | "create" | "delete" | "stat" | "access" | "rename" | "link";
  path?: string;
  path2?: string; // for rename/link operations
  flags?: string;
  mode?: number;
  result?: number;
}

// Open flags
const O_RDONLY = 0x0000;
const O_WRONLY = 0x0001;
const O_RDWR = 0x0002;
const O_CREAT = 0x0200;
const O_TRUNC = 0x0400;
const O_EXCL = 0x0800;
const O_APPEND = 0x0008;

function formatOpenFlags(flags: number): string {
  const parts: string[] = [];

  const accessMode = flags & 0x3;
  if (accessMode === O_RDONLY) parts.push("O_RDONLY");
  else if (accessMode === O_WRONLY) parts.push("O_WRONLY");
  else if (accessMode === O_RDWR) parts.push("O_RDWR");

  if (flags & O_CREAT) parts.push("O_CREAT");
  if (flags & O_TRUNC) parts.push("O_TRUNC");
  if (flags & O_EXCL) parts.push("O_EXCL");
  if (flags & O_APPEND) parts.push("O_APPEND");

  return parts.length > 0 ? parts.join("|") : `0x${flags.toString(16)}`;
}

function q(s: string | null | undefined): string {
  return s ? `"${s}"` : "NULL";
}

/**
 * Monitor file system operations (open, create, delete, stat, access, rename, link)
 * Excludes write and fcntl as they are too verbose
 */
export function monitor() {
  const hooks: InvocationListener[] = [];
  const kernel = Process.findModuleByName("libsystem_kernel.dylib");
  if (!kernel) return [];

  // Hook open
  const openPtr = kernel.findExportByName("open");
  if (openPtr) {
    hooks.push(
      Interceptor.attach(openPtr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
          this.flags = args[1].toInt32();
        },
        onLeave(retval) {
          const fd = retval.toInt32();
          const isCreate = (this.flags & O_CREAT) !== 0;
          const flagsStr = formatOpenFlags(this.flags);

          send({
            subject: "hook",
            category: "fileops",
            symbol: "open",
            dir: "leave",
            line: `open(${q(this.path)}, ${flagsStr}) = ${fd}`,
            op: isCreate ? "create" : "open",
            path: this.path,
            flags: flagsStr,
            result: fd,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook openat
  const openatPtr = kernel.findExportByName("openat");
  if (openatPtr) {
    hooks.push(
      Interceptor.attach(openatPtr, {
        onEnter(args) {
          this.path = args[1].readUtf8String();
          this.flags = args[2].toInt32();
        },
        onLeave(retval) {
          const fd = retval.toInt32();
          const isCreate = (this.flags & O_CREAT) !== 0;
          const flagsStr = formatOpenFlags(this.flags);

          send({
            subject: "hook",
            category: "fileops",
            symbol: "openat",
            dir: "leave",
            line: `openat(AT_FDCWD, ${q(this.path)}, ${flagsStr}) = ${fd}`,
            op: isCreate ? "create" : "open",
            path: this.path,
            flags: flagsStr,
            result: fd,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook unlink (delete file)
  const unlinkPtr = kernel.findExportByName("unlink");
  if (unlinkPtr) {
    hooks.push(
      Interceptor.attach(unlinkPtr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "unlink",
            dir: "leave",
            line: `unlink(${q(this.path)}) = ${result}`,
            op: "delete",
            path: this.path,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook unlinkat
  const unlinkatPtr = kernel.findExportByName("unlinkat");
  if (unlinkatPtr) {
    hooks.push(
      Interceptor.attach(unlinkatPtr, {
        onEnter(args) {
          this.path = args[1].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "unlinkat",
            dir: "leave",
            line: `unlinkat(AT_FDCWD, ${q(this.path)}) = ${result}`,
            op: "delete",
            path: this.path,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook rmdir
  const rmdirPtr = kernel.findExportByName("rmdir");
  if (rmdirPtr) {
    hooks.push(
      Interceptor.attach(rmdirPtr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "rmdir",
            dir: "leave",
            line: `rmdir(${q(this.path)}) = ${result}`,
            op: "delete",
            path: this.path,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook stat
  const statPtr = kernel.findExportByName("stat");
  if (statPtr) {
    hooks.push(
      Interceptor.attach(statPtr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "stat",
            dir: "leave",
            line: `stat(${q(this.path)}) = ${result}`,
            op: "stat",
            path: this.path,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook stat64
  const stat64Ptr = kernel.findExportByName("stat64");
  if (stat64Ptr) {
    hooks.push(
      Interceptor.attach(stat64Ptr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "stat64",
            dir: "leave",
            line: `stat64(${q(this.path)}) = ${result}`,
            op: "stat",
            path: this.path,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook lstat
  const lstatPtr = kernel.findExportByName("lstat");
  if (lstatPtr) {
    hooks.push(
      Interceptor.attach(lstatPtr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "lstat",
            dir: "leave",
            line: `lstat(${q(this.path)}) = ${result}`,
            op: "stat",
            path: this.path,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook lstat64
  const lstat64Ptr = kernel.findExportByName("lstat64");
  if (lstat64Ptr) {
    hooks.push(
      Interceptor.attach(lstat64Ptr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "lstat64",
            dir: "leave",
            line: `lstat64(${q(this.path)}) = ${result}`,
            op: "stat",
            path: this.path,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook access
  const accessPtr = kernel.findExportByName("access");
  if (accessPtr) {
    hooks.push(
      Interceptor.attach(accessPtr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
          this.mode = args[1].toInt32();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "access",
            dir: "leave",
            line: `access(${q(this.path)}, ${this.mode}) = ${result}`,
            op: "access",
            path: this.path,
            mode: this.mode,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook faccessat
  const faccessatPtr = kernel.findExportByName("faccessat");
  if (faccessatPtr) {
    hooks.push(
      Interceptor.attach(faccessatPtr, {
        onEnter(args) {
          this.path = args[1].readUtf8String();
          this.mode = args[2].toInt32();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "faccessat",
            dir: "leave",
            line: `faccessat(AT_FDCWD, ${q(this.path)}, ${this.mode}) = ${result}`,
            op: "access",
            path: this.path,
            mode: this.mode,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook rename
  const renamePtr = kernel.findExportByName("rename");
  if (renamePtr) {
    hooks.push(
      Interceptor.attach(renamePtr, {
        onEnter(args) {
          this.oldPath = args[0].readUtf8String();
          this.newPath = args[1].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "rename",
            dir: "leave",
            line: `rename(${q(this.oldPath)}, ${q(this.newPath)}) = ${result}`,
            op: "rename",
            path: this.oldPath,
            path2: this.newPath,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook renameat
  const renameatPtr = kernel.findExportByName("renameat");
  if (renameatPtr) {
    hooks.push(
      Interceptor.attach(renameatPtr, {
        onEnter(args) {
          this.oldPath = args[1].readUtf8String();
          this.newPath = args[3].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "renameat",
            dir: "leave",
            line: `renameat(AT_FDCWD, ${q(this.oldPath)}, AT_FDCWD, ${q(this.newPath)}) = ${result}`,
            op: "rename",
            path: this.oldPath,
            path2: this.newPath,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook mkdir
  const mkdirPtr = kernel.findExportByName("mkdir");
  if (mkdirPtr) {
    hooks.push(
      Interceptor.attach(mkdirPtr, {
        onEnter(args) {
          this.path = args[0].readUtf8String();
          this.mode = args[1].toInt32();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "mkdir",
            dir: "leave",
            line: `mkdir(${q(this.path)}, 0${this.mode.toString(8)}) = ${result}`,
            op: "create",
            path: this.path,
            mode: this.mode,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook mkdirat
  const mkdiratPtr = kernel.findExportByName("mkdirat");
  if (mkdiratPtr) {
    hooks.push(
      Interceptor.attach(mkdiratPtr, {
        onEnter(args) {
          this.path = args[1].readUtf8String();
          this.mode = args[2].toInt32();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "mkdirat",
            dir: "leave",
            line: `mkdirat(AT_FDCWD, ${q(this.path)}, 0${this.mode.toString(8)}) = ${result}`,
            op: "create",
            path: this.path,
            mode: this.mode,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook link
  const linkPtr = kernel.findExportByName("link");
  if (linkPtr) {
    hooks.push(
      Interceptor.attach(linkPtr, {
        onEnter(args) {
          this.oldPath = args[0].readUtf8String();
          this.newPath = args[1].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "link",
            dir: "leave",
            line: `link(${q(this.oldPath)}, ${q(this.newPath)}) = ${result}`,
            op: "link",
            path: this.oldPath,
            path2: this.newPath,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  // Hook symlink
  const symlinkPtr = kernel.findExportByName("symlink");
  if (symlinkPtr) {
    hooks.push(
      Interceptor.attach(symlinkPtr, {
        onEnter(args) {
          this.oldPath = args[0].readUtf8String();
          this.newPath = args[1].readUtf8String();
        },
        onLeave(retval) {
          const result = retval.toInt32();
          send({
            subject: "hook",
            category: "fileops",
            symbol: "symlink",
            dir: "leave",
            line: `symlink(${q(this.oldPath)}, ${q(this.newPath)}) = ${result}`,
            op: "link",
            path: this.oldPath,
            path2: this.newPath,
            result,
            backtrace: bt(this.context),
          } as Message);
        },
      }),
    );
  }

  return hooks;
}

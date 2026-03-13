import ObjC from "frida-objc-bridge";
import Java from "frida-java-bridge";

import { mkdirp as objcMkdirp } from "./fruity/modules/fs.js";
import { mkdirp as javaMkdirp } from "./droid/modules/fs.js";
import { parseMachO, readEncryptionInfo } from "./fruity/parser/macho.js";

import fs from "fs";
import path from "path";
import RemoteStreamController, { type Packet } from "frida-remote-stream";

rpc.exports.len = function (path: string) {
  return fs.statSync(path).size;
};

/**
 * Get the uncompressed size of an entry inside a ZIP (APK) file.
 */
rpc.exports.zipLen = function (apkPath: string, entryName: string): number {
  let result = -1;
  Java.perform(() => {
    const ZipFile = Java.use("java.util.zip.ZipFile");
    const zip = ZipFile.$new(apkPath);
    try {
      const entry = zip.getEntry(entryName);
      if (!entry) throw new Error(`Entry not found: ${entryName}`);
      result = Number(entry.getSize());
    } finally {
      zip.close();
    }
  });
  return result;
};

/**
 * Stream a ZIP entry via frida-remote-stream.
 */
rpc.exports.pullZip = function (apkPath: string, entryName: string) {
  Java.perform(() => {
    const ZipFile = Java.use("java.util.zip.ZipFile");
    const zip = ZipFile.$new(apkPath);
    try {
      const entry = zip.getEntry(entryName);
      if (!entry) throw new Error(`Entry not found: ${entryName}`);

      const inputStream = zip.getInputStream(entry);
      const buffer = Java.array("byte", new Array(DUMP_CHUNK_SIZE).fill(0));
      const label = `${Process.id}:zip:${apkPath}:${entryName}`;
      const controller = new RemoteStreamController();

      controller.events.on("send", ({ stanza, data }: Packet) => {
        send(
          {
            name: "+stream",
            payload: stanza,
          },
          data?.buffer as ArrayBuffer,
        );
      });

      function onStreamMessage(
        message: { payload: { [key: string]: string } },
        data: ArrayBuffer | null,
      ) {
        controller.receive({
          stanza: message.payload,
          data: data as unknown as Buffer<ArrayBufferLike>,
        });
        recv("+stream", onStreamMessage);
      }
      recv("+stream", onStreamMessage);

      const writable = controller.open(label, { meta: { type: "data" } });

      const env = Java.vm.getEnv();
      const wrapper = buffer as unknown as Java.Wrapper;
      const bufHandle = wrapper.$handle ?? wrapper.$h;

      let len: number;
      while ((len = inputStream.read(buffer)) !== -1) {
        // Fast JNI copy: GetByteArrayElements instead of element-by-element
        const ptr = env.getByteArrayElements(bufHandle);
        const chunk = ptr.readByteArray(len)!;
        env.releaseByteArrayElements(bufHandle, ptr);
        writable.write(Buffer.from(chunk));
      }
      writable.end();
      inputStream.close();
    } finally {
      zip.close();
    }
  });
};

const LC_ENCRYPTION_INFO = 0x21;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const DUMP_CHUNK_SIZE = 1024 * 1024; // 1MB

function waitForAck() {
  recv("ack", () => {}).wait();
}

function sendChunk(data: ArrayBuffer) {
  send({ event: "data" }, data);
  waitForAck();
}

function streamFromDisk(
  path: string,
  offset: number,
  size: number,
  patch?: { offset: number; data: ArrayBuffer },
) {
  const fd = new File(path, "r");
  try {
    fd.seek(offset);
    let remaining = size;
    let filePos = offset;

    while (remaining > 0) {
      const toRead = Math.min(DUMP_CHUNK_SIZE, remaining);
      const chunk = fd.readBytes(toRead);

      if (patch && filePos <= patch.offset && patch.offset < filePos + toRead) {
        const patchOffset = patch.offset - filePos;
        const dst = new Uint8Array(chunk);
        const src = new Uint8Array(patch.data);
        for (let i = 0; i < src.length; i++) {
          dst[patchOffset + i] = src[i];
        }
      }

      sendChunk(chunk);
      remaining -= toRead;
      filePos += toRead;
    }
  } finally {
    fd.close();
  }
}

function streamFromMemory(base: NativePointer, offset: number, size: number) {
  let remaining = size;
  let p = base.add(offset);

  while (remaining > 0) {
    const toRead = Math.min(DUMP_CHUNK_SIZE, remaining);
    const chunk = p.readByteArray(toRead);
    if (chunk) sendChunk(chunk);
    remaining -= toRead;
    p = p.add(toRead);
  }
}

rpc.exports.dump = function (filePath: string): void {
  if (Process.platform !== "darwin") {
    send({ event: "error", message: "dump is only supported on iOS" });
    return;
  }

  let fileSize: number;
  try {
    fileSize = fs.statSync(filePath).size;
  } catch {
    send({ event: "error", message: `file not found: ${filePath}` });
    return;
  }

  const mod = Module.load(filePath);
  const macho = parseMachO(mod);
  const encLC = macho.loadCommands.find(
    (lc) => lc.cmd === LC_ENCRYPTION_INFO_64 || lc.cmd === LC_ENCRYPTION_INFO,
  );
  const encInfo = encLC ? readEncryptionInfo(encLC) : null;

  if (!encInfo || encInfo.cryptid === 0) {
    send({ event: "info", size: fileSize });
    waitForAck();
    streamFromDisk(filePath, 0, fileSize);
    send({ event: "end" });
    return;
  }

  const range = Process.findRangeByAddress(mod.base);
  const fatOffset = range!.file!.offset;
  const encCmdOffset = encLC!.ptr.sub(mod.base).toInt32();

  send({ event: "info", size: fileSize });
  waitForAck();

  // Phase A: disk [0, fatOffset+cryptoff) — with LC_ENCRYPTION_INFO patch
  const phaseASize = fatOffset + encInfo.cryptoff;
  if (phaseASize > 0) {
    const zeroPatch = new ArrayBuffer(12);
    streamFromDisk(filePath, 0, phaseASize, {
      offset: fatOffset + encCmdOffset + 8,
      data: zeroPatch,
    });
  }

  // Phase B: memory [mod.base+cryptoff, mod.base+cryptoff+cryptsize) — decrypted
  streamFromMemory(mod.base, encInfo.cryptoff, encInfo.cryptsize);

  // Phase C: disk [fatOffset+cryptoff+cryptsize, fileSize) — remainder
  const phaseCStart = fatOffset + encInfo.cryptoff + encInfo.cryptsize;
  const phaseCSize = fileSize - phaseCStart;
  if (phaseCSize > 0) {
    streamFromDisk(filePath, phaseCStart, phaseCSize);
  }

  send({ event: "end" });
};

/**
 * download a file via stream
 * @param path source path
 */

rpc.exports.pull = function (path: string) {
  const label = `${Process.id}:${path}`;
  const controller = new RemoteStreamController();
  controller.events.on("send", ({ stanza, data }: Packet) => {
    send(
      {
        name: "+stream",
        payload: stanza,
      },
      data?.buffer as ArrayBuffer,
    );
  });

  function onStreamMessage(
    message: { payload: { [key: string]: string } },
    data: ArrayBuffer | null,
  ) {
    controller.receive({
      stanza: message.payload,
      data: data as unknown as Buffer<ArrayBufferLike>,
    });
    recv("+stream", onStreamMessage);
  }

  recv("+stream", onStreamMessage);
  fs.createReadStream(path).pipe(
    controller.open(label, { meta: { type: "data" } }),
  );
};

function mkdirp(path: string) {
  if (ObjC.available) return objcMkdirp(path);
  else if (Java.available) return javaMkdirp(path);

  throw new Error("mkdirp is not supported on this platform");
}

/**
 * upload a file via stream
 * @param path destination path
 */
rpc.exports.push = function (dest: string) {
  const dir = path.dirname(dest);
  mkdirp(dir);

  const streams = new RemoteStreamController();

  streams.events.on("send", ({ stanza, data }: Packet) => {
    send(
      {
        name: "+stream",
        payload: stanza,
      },
      data?.buffer as ArrayBuffer,
    );
  });

  function onStreamMessage(
    message: { payload: Packet },
    data: ArrayBuffer | null,
  ) {
    const packet: Packet = {
      stanza: message.payload,
      data: data ? Buffer.from(data) : null,
    };
    streams.receive(packet);
    recv("+stream", onStreamMessage);
  }
  recv("+stream", onStreamMessage);

  streams.events.on("stream", (stream) =>
    stream.pipe(fs.createWriteStream(dest)),
  );
};

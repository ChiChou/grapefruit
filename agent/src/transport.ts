import fs from "fs";
import RemoteStreamController, { type Packet } from "frida-remote-stream";

rpc.exports.len = function (path: string) {
  return fs.statSync(path).size;
};

const MH_MAGIC_64 = 0xfeedfacf;
const LC_ENCRYPTION_INFO_64 = 0x2c;
const HEADER_SIZE_64 = 8 * 4; // 32 bytes
const DUMP_CHUNK_SIZE = 1024 * 1024; // 1MB

interface EncryptionInfo {
  cryptoff: number;
  cryptsize: number;
  cryptid: number;
  encCmdOffset: number;
}

function parseEncryptionInfo(path: string): EncryptionInfo | null {
  const fd = new File(path, "r");
  try {
    const headerBuf = fd.readBytes(HEADER_SIZE_64);
    const header = new DataView(headerBuf);

    const magic = header.getUint32(0, true);
    if (magic !== MH_MAGIC_64) return null;

    const ncmds = header.getUint32(16, true);
    const sizeOfCmds = header.getUint32(20, true);

    const cmdsBuf = fd.readBytes(sizeOfCmds);
    const cmds = new DataView(cmdsBuf);

    let offset = 0;
    for (let i = 0; i < ncmds && offset + 8 <= cmdsBuf.byteLength; i++) {
      const cmd = cmds.getUint32(offset, true);
      const cmdsize = cmds.getUint32(offset + 4, true);

      if (cmd === LC_ENCRYPTION_INFO_64) {
        return {
          cryptoff: cmds.getUint32(offset + 8, true),
          cryptsize: cmds.getUint32(offset + 12, true),
          cryptid: cmds.getUint32(offset + 16, true),
          encCmdOffset: HEADER_SIZE_64 + offset,
        };
      }

      offset += cmdsize;
    }

    return null;
  } finally {
    fd.close();
  }
}

function waitForAck() {
  recv("ack", () => {}).wait();
}

function sendChunk(data: ArrayBuffer) {
  send({ event: "data" }, data);
  waitForAck();
}

function streamFromDisk(path: string, offset: number, size: number, patch?: { offset: number; data: ArrayBuffer }) {
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

rpc.exports.dump = function (path: string): void {
  let fileSize: number;
  try {
    fileSize = fs.statSync(path).size;
  } catch {
    send({ event: "error", message: `file not found: ${path}` });
    return;
  }

  const encInfo = parseEncryptionInfo(path);

  if (!encInfo || encInfo.cryptid === 0) {
    send({ event: "info", size: fileSize });
    waitForAck();
    streamFromDisk(path, 0, fileSize);
    send({ event: "end" });
    return;
  }

  const mod = Module.load(path);
  const range = Process.findRangeByAddress(mod.base);
  const fatOffset = range!.file!.offset;

  send({ event: "info", size: fileSize });
  waitForAck();

  // Phase A: disk [0, fatOffset+cryptoff) — with LC_ENCRYPTION_INFO patch
  const phaseASize = fatOffset + encInfo.cryptoff;
  if (phaseASize > 0) {
    const zeroPatch = new ArrayBuffer(12);
    streamFromDisk(path, 0, phaseASize, {
      offset: fatOffset + encInfo.encCmdOffset + 8,
      data: zeroPatch,
    });
  }

  // Phase B: memory [mod.base+cryptoff, mod.base+cryptoff+cryptsize) — decrypted
  streamFromMemory(mod.base, encInfo.cryptoff, encInfo.cryptsize);

  // Phase C: disk [fatOffset+cryptoff+cryptsize, fileSize) — remainder
  const phaseCStart = fatOffset + encInfo.cryptoff + encInfo.cryptsize;
  const phaseCSize = fileSize - phaseCStart;
  if (phaseCSize > 0) {
    streamFromDisk(path, phaseCStart, phaseCSize);
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

/**
 * upload a file via stream
 * @param path destination path
 */
rpc.exports.push = function (path: string) {
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
    stream.pipe(fs.createWriteStream(path)),
  );
};

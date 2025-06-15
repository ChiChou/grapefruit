import fs from "fs";

interface UploadTrunk {
  index: number;
  size: number;
}

class SessionAllocator {
  #value: number;
  constructor() {
    this.#value = 0;
  }

  add(): number {
    return this.#value++;
  }

  toString(): string {
    return this.#value.toString();
  }

  static #shared: SessionAllocator = new SessionAllocator();
  static get shared(): SessionAllocator {
    return SessionAllocator.#shared;
  }
}

export function upload(destination: string, size: number) {
  const session = SessionAllocator.shared.add();
  const writer = fs.createWriteStream(destination, "binary");

  let counter = 0;
  let received = 0;

  let cb = (msg: UploadTrunk, data: ArrayBuffer | null) => {
    if (!data) throw new Error("Received null data for upload trunk");
    if (msg.index !== counter)
      throw new Error(
        `Received upload trunk with index ${msg.index}, expected ${counter}`,
      );

    writer.write(Buffer.from(data));
    counter++;
    received += msg.size;

    if (received > size)
      throw new Error(
        `Received more data than expected: ${received} > ${size}`,
      );

    if (received == size) {
      writer.end();
      send({
        subject: "upload",
        event: "end",
        session,
      });
    } else {
      recv(`upload-${session}-${counter}`, cb);
      send({
        subject: "upload",
        event: "drain",
        session,
        index: counter,
      });
    }
  };

  recv(`upload-${session}-${counter}`, cb);
  send({
    subject: "upload",
    event: "start",
    session,
  });

  writer.on("error", (err) => {
    send({
      subject: "upload",
      event: "error",
      error: err.message,
      session,
    });
    writer.end();
  });

  return {
    session,
  };
}

export function download(path: string) {
  const session = SessionAllocator.shared.add();
  const stats = fs.statSync(path);
  const reader = fs.createReadStream(path, "binary");
  reader.on("data", (trunk) => {
    send({
      subject: "download",
      event: "trunk",
      session,
    });
  });
  reader.on("end", () => {
    send({});
    reader.destroy();
  });
  reader.on("error", () => {
    send({
      subject: "download",
      event: "error",
      session,
    });
  });

  return {
    size: stats.size,
    session,
  };
}

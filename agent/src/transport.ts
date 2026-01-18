import fs from "fs";
import RemoteStreamController, { type Packet } from "frida-remote-stream";

rpc.exports.len = function (path: string) {
  return fs.statSync(path).size;
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

import { getGlobalExport } from "@/lib/polyfill.js";

// sys/fcntl.h
const F_SETFL = 4;
const O_NONBLOCK = 0x0004;

const stderr = 2;
const SIZEOF_INT = 4; // for mac & iOS

const subject = "syslog";
const fildes = Memory.alloc(SIZEOF_INT * 2);

let stream: UnixInputStream | null = null;

export function start() {
  const close = new NativeFunction(getGlobalExport("close"), "int", ["int"]);
  const pipe = new NativeFunction(getGlobalExport("pipe"), "int", ["pointer"]);
  const dup2 = new NativeFunction(getGlobalExport("dup2"), "int", [
    "int",
    "int",
  ]);
  const fcntl = new NativeFunction(getGlobalExport("fcntl"), "int", [
    "int",
    "int",
    "int",
  ]);

  if (stream) return;

  pipe(fildes);

  const input = fildes.readInt();
  const output = fildes.add(SIZEOF_INT).readInt();

  dup2(output, stderr);
  close(output);
  fcntl(input, F_SETFL, O_NONBLOCK);

  stream = new UnixInputStream(input);

  function read() {
    if (!stream) return;

    stream.read(4096).then((buf) => {
      if (buf.byteLength) send({ subject }, buf);
      setImmediate(read);
    });
  }

  setImmediate(read);

  Script.bindWeak(globalThis, stop);
}

export function stop() {
  if (stream) {
    stream.close();
    stream = null;
  }
}

const close = new NativeFunction(Module.findExportByName(null, 'close')!, 'int', ['int'])
const pipe = new NativeFunction(Module.findExportByName(null, 'pipe')!, 'int', ['pointer'])
const dup2 = new NativeFunction(Module.findExportByName(null, 'dup2')!, 'int', ['int', 'int'])
const fcntl = new NativeFunction(Module.findExportByName(null, 'fcntl')!, 'int', ['int', 'int', 'int'])

// sys/fcntl.h
const F_SETFL = 4
const O_NONBLOCK = 0x0004

const stderr = 2;
const SIZEOF_INT = 4; // for mac & iOS

const subject = 'syslog'
const fildes = Memory.alloc(SIZEOF_INT * 2)

let stream: UnixInputStream

export function start() {
  pipe(fildes)

  const input = fildes.readInt()
  const output = fildes.add(SIZEOF_INT).readInt()

  dup2(output, stderr)
  close(output)
  fcntl(input, F_SETFL, O_NONBLOCK)

  stream = new UnixInputStream(input)

  function read() {
    stream.read(4096).then((buf) => {
      if (buf.byteLength)
        send({ subject }, buf)

      setImmediate(read)
    })
  }

  setImmediate(read)
}

export function stop() {
  if (stream)
    stream.close()
}

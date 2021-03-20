/* eslint-disable @typescript-eslint/no-explicit-any */
import * as frida from 'frida'

import bplistCreate from 'bplist-creator';
import * as bplistParser from 'bplist-parser';
import * as plist from 'plist';


// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parse(data: Buffer): any {
  const magic = data.slice(0, 6).toString().toLowerCase();
  if (magic == '<?xml ') {
    return plist.parse(data.toString());
  } else if (magic == 'bplist') {
    return bplistParser.parseBuffer(data);
  }
  throw new Error(`Unknown magic "${magic}"`);
}

const I = {
  pack(v: number): Buffer {
    const buf = Buffer.allocUnsafe(4);
    buf.writeUInt32BE(v);
    return buf;
  },
  unpack(buf: Buffer): number {
    return buf.readUInt32BE();
  }
}

export class Lockdown {
  io: frida.IOStream;

  synchronized = false;
  dl = false;

  constructor(public device: frida.Device, public service: string = '') { }

  async connect(): Promise<void> {
    this.io = await this.device.openChannel(`lockdown:${this.service}`)

    if (this.service.length > 0) {
      await this.exchange();
      this.dl = true;
    }
  }

  async exchange(): Promise<void> {
    const MAGIC = 'DLMessageVersionExchange';

    const [[magic, major, minor]] = await this.recv() as [[string, number, number]]
    if (magic !== MAGIC)
      throw new RangeError(`unexpected magic ${magic}`);

    if (minor !== 0)
      throw new RangeError(`unexpected minor version ${minor}`);

    this.send([MAGIC, 'DLVersionsOk', major]);

    const [[ready,],] = await this.recv() as [[string, ]]
    if (ready !== 'DLMessageDeviceReady')
      throw new Error('Malformed protocol')
  }

  fetch(size: number): Promise<Buffer> {
    const retry = (): Promise<Buffer> => new Promise((resolve, reject) =>
      this.io
        .once('error', reject)
        .once('readable', () => {
          this.io.off('error', reject)
          resolve(this.io.read(size) || retry())
        })
    );
    return this.io.read(size) || retry();
  }

  async recv(): Promise<any> {
    const retrieve = async (): Promise<any> => {
      if (this.synchronized)
        throw new Error('Only one read action at a time');

      this.synchronized = true
      const size = I.unpack(await this.fetch(4));
      const data = await this.fetch(size);
      this.synchronized = false;
      const obj = parse(data);
      return this.dl ? obj[0] : obj
    }

    const packet = await retrieve();
    if (this.dl) {
      const [magic, msg] = packet as [string, object];
      if (magic !== 'DLMessageProcessMessage')
        throw new RangeError(`unexpected magic ${magic}`)
      return msg;
    }

    return packet;
  }

  send(msg: object): void {
    const wrapped = this.dl ? ['DLMessageProcessMessage', msg] : msg;
    const buf = bplistCreate(wrapped);
    this.io.write(I.pack(buf.length));
    this.io.write(buf);
  }

  close(): void {
    this.io.destroy();
  }
}

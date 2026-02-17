import { fromByteArray } from "base64-js";

declare global {
  interface ArrayBuffer {
    toJSON(): { type: "ArrayBuffer"; base64: string; length: number };
  }
}

// workaround: send() cannot serialize ArrayBuffer
// this function is just to show more friendly representation of an ArrayBuffer
// the agent should always use send({}, data) for blobs
ArrayBuffer.prototype.toJSON = function () {
  const limit = 32;
  const u8 = new Uint8Array(this);
  let base64 = fromByteArray(u8);
  if (base64.length > limit) base64 = base64.slice(0, limit) + "...";
  return { type: "ArrayBuffer", base64, length: this.byteLength };
};

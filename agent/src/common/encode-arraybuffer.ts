import { fromByteArray } from "base64-js";

declare global {
  interface ArrayBuffer {
    toJSON(): { type: "ArrayBuffer"; base64: string };
  }
}

// workaround: send() cannot serialize ArrayBuffer
ArrayBuffer.prototype.toJSON = function () {
  const u8 = new Uint8Array(this);
  return { type: "ArrayBuffer", base64: fromByteArray(u8) };
};

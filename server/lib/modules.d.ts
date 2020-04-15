/* eslint-disable @typescript-eslint/no-explicit-any */

declare module 'bplist-creator' {
  export default function(obj: any): Buffer;
}

declare module 'bplist-parser' {
  export function parseBuffer(data: Buffer): any;
}

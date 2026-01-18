/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Socket } from "socket.io-client";

import type {
  RemoteRPC,
  RPCRoute,
} from "../../../agent/types/fruity/registry.d.ts";

export interface SessionClientEvents {
  ready: (pid: number) => void;
}

export interface SessionServerEvents {
  rpc: (
    mod: string,
    method: string,
    args: any[],
    ack: (err: Error, result: any) => void,
  ) => void;
}

// RemoteRPC already converts methods to Promise-based
export type AsyncFruityRPC = RemoteRPC<RPCRoute>;

export function createAPI(
  socket: Socket<SessionClientEvents, SessionServerEvents>,
): AsyncFruityRPC {
  return new Proxy({} as AsyncFruityRPC, {
    get(_target, namespace: string) {
      return new Proxy(
        {},
        {
          get(_nsTarget, method: string) {
            return (...args: any[]) => {
              return new Promise((resolve, reject) => {
                socket.emit(
                  "rpc",
                  namespace,
                  method,
                  args,
                  (err: Error, result: any) => {
                    if (err) reject(err);
                    else resolve(result);
                  },
                );
              });
            };
          },
        },
      );
    },
  });
}

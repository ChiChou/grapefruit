/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Socket } from "socket.io-client";

import type { RemoteRPC as FruityRPC } from "../../../agent/types/fruity/registry.d.ts";

interface SessionClientEvents {
  ready: () => void;
}

interface SessionServerEvents {
  rpc: (
    mod: string,
    method: string,
    args: any[],
    ack: (err: Error, result: any) => void,
  ) => void;
}

// Convert FruityRPC to async promise-based API
type AsyncFruityRPC = {
  [Namespace in keyof FruityRPC]: {
    [Method in keyof FruityRPC[Namespace]]: FruityRPC[Namespace][Method] extends (
      ...args: infer Args
    ) => infer Return
      ? (...args: Args) => Promise<Return>
      : never;
  };
};

export default function createRPC(
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

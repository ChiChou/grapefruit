/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Socket } from "socket.io-client";

import type {
  RemoteRPC,
  RPCRoute,
} from "../../../agent/types/fruity/registry.d.ts";

export interface SessionClientEvents {
  ready: (pid: number) => void;
  log: (level: string, text: string) => void;
  syslog: (text: string) => void;
  invalid: () => void;
}

export interface SessionServerEvents {
  rpc: (
    mod: string,
    method: string,
    args: any[],
    ack: (err: Error, result: any) => void,
  ) => void;
}

export type AsyncFruityRPC = RemoteRPC<RPCRoute>;

export function createAPI(
  socket: Socket<SessionClientEvents, SessionServerEvents>,
): AsyncFruityRPC {
  let ready = false;
  const pending: Array<{ run: () => void; reject: (err: Error) => void }> = [];

  socket.on("ready", () => {
    ready = true;
    pending.forEach((operation) => operation.run());
    pending.length = 0;
  });

  socket.on("disconnect", () => {
    ready = false;
    const err = new Error("socket disconnected");
    pending.forEach((operation) => operation.reject(err));
    pending.length = 0;
  });

  function executor(
    namespace: string,
    method: string,
    args: any[],
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      const run = () => {
        console.debug(
          "rpc",
          "connected=" + socket.connected,
          namespace + "." + method,
          args.join(" ,"),
        );
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
      };

      if (ready) run();
      else pending.push({ run, reject });
    });
  }

  return new Proxy({} as AsyncFruityRPC, {
    get(_target, namespace: string) {
      return new Proxy(
        {},
        {
          get(_nsTarget, method: string) {
            return (...args: any[]) => executor(namespace, method, args);
          },
        },
      );
    },
  });
}

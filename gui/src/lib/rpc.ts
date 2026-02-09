/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Socket } from "socket.io-client";

import type {
  RemoteRPC,
  RPCRoute as FruityRPCRoute,
} from "../../../agent/types/fruity/registry.d.ts";

import type { RPCRoute as DroidRPCRoute } from "../../../agent/types/droid/registry.d.ts";

import type { BaseMessage as BaseHookMessage } from "../../../agent/types/fruity/hooks/context";

export interface SessionClientEvents {
  ready: (pid: number) => void;
  log: (level: string, text: string) => void;
  syslog: (text: string) => void;
  invalid: () => void;
  hook: (message: BaseHookMessage) => void;
  httplog: (event: any) => void;
}

export interface SessionServerEvents {
  rpc: (
    mod: string,
    method: string,
    args: any[],
    ack: (err: Error, result: any) => void,
  ) => void;
}

export type AsyncFruityRPC = RemoteRPC<FruityRPCRoute>;
export type AsyncDroidRPC = RemoteRPC<DroidRPCRoute>;

type Platform = "fruity" | "droid";

function createExecutor(
  socket: Socket<SessionClientEvents, SessionServerEvents>,
) {
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

  return function executor(
    namespace: string,
    method: string,
    args: any[],
  ): Promise<any> {
    return new Promise((resolve, reject) => {
      const run = () => {
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
  };
}

function createProxy<T extends object>(
  executor: (namespace: string, method: string, args: any[]) => Promise<any>,
): T {
  return new Proxy({} as T, {
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

function createThrowingProxy<T extends object>(
  expectedPlatform: Platform,
  actualPlatform: Platform,
): T {
  const message = `Cannot use ${expectedPlatform} API when connected to ${actualPlatform} platform`;
  return new Proxy({} as T, {
    get() {
      return new Proxy(
        {},
        {
          get() {
            return () => {
              throw new Error(message);
            };
          },
        },
      );
    },
  });
}

export interface PlatformAPIs {
  fruity: AsyncFruityRPC;
  droid: AsyncDroidRPC;
}

/**
 * Create platform-specific RPC APIs.
 * Returns both fruity and droid typed endpoints.
 * Only the matching platform's API actually works - the other throws on access.
 */
export function createAPI(
  socket: Socket<SessionClientEvents, SessionServerEvents>,
  platform: Platform,
): PlatformAPIs {
  const executor = createExecutor(socket);

  if (platform === "fruity") {
    return {
      fruity: createProxy<AsyncFruityRPC>(executor),
      droid: createThrowingProxy<AsyncDroidRPC>("droid", "fruity"),
    };
  } else {
    return {
      fruity: createThrowingProxy<AsyncFruityRPC>("fruity", "droid"),
      droid: createProxy<AsyncDroidRPC>(executor),
    };
  }
}

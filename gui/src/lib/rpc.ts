/* eslint-disable @typescript-eslint/no-explicit-any */
import type { Socket } from "socket.io-client";

import type {
  RemoteRPC,
  RPCRoute as FruityRPCRoute,
} from "@agent/fruity/registry";

import type { RPCRoute as DroidRPCRoute } from "@agent/droid/registry";

import type { BaseMessage as BaseHookMessage } from "@agent/common/hooks/context";
import type { JNIEvent } from "@agent/droid/hooks/jni";

interface NSURLEventBase {
  requestId: string;
  timestamp: number;
}

interface RequestWillBeSentEvent extends NSURLEventBase {
  event: "requestWillBeSent";
  request: {
    method: string;
    url: string;
    headers: Record<string, string>;
    body?: string;
  };
  redirectResponse?: {
    url?: string;
    mimeType?: string;
    expectedContentLength: number;
    statusCode?: number;
    headers?: Record<string, string>;
  };
}

interface ResponseReceivedEvent extends NSURLEventBase {
  event: "responseReceived";
  response: {
    url?: string;
    mimeType?: string;
    expectedContentLength: number;
    statusCode?: number;
    headers?: Record<string, string>;
  };
}

interface DataReceivedEvent extends NSURLEventBase {
  event: "dataReceived";
  dataLength: string;
}

interface LoadingFinishedEvent extends NSURLEventBase {
  event: "loadingFinished";
  hasBody?: boolean;
}

interface LoadingFailedEvent extends NSURLEventBase {
  event: "loadingFailed";
  error: string;
}

interface MechanismEvent extends NSURLEventBase {
  event: "mechanism";
  mechanism: string;
}

interface WebSocketMessageEvent extends NSURLEventBase {
  event: "webSocketSend" | "webSocketReceive";
  messageType: "data" | "string";
  dataLength?: number;
  message?: string;
  error?: string;
}

export type NSURLEvent =
  | RequestWillBeSentEvent
  | ResponseReceivedEvent
  | DataReceivedEvent
  | LoadingFinishedEvent
  | LoadingFailedEvent
  | MechanismEvent
  | WebSocketMessageEvent;

import type { XPCNode, XPCNodeType } from "@agent/fruity/hooks/xpc";
export type { XPCNode, XPCNodeType };

export interface NSXPCMessage {
  type: "nsxpc";
  sel: string;
  args: string[];
  description: string;
}

export function isNSXPCMessage(
  msg: XPCNode | NSXPCMessage,
): msg is NSXPCMessage {
  return (msg as NSXPCMessage).type === "nsxpc";
}

export interface XPCSocketEvent {
  event: "received" | "sent";
  dir: "<" | ">";
  name?: string;
  peer?: number;
  message: XPCNode | NSXPCMessage;
  backtrace?: string[];
}

export interface MemoryScanEvent {
  event: "match" | "progress" | "done";
  address?: string;
  size?: number;
  current?: number;
  total?: number;
  count?: number;
}

export interface SessionClientEvents {
  ready: (pid: number) => void;
  denied: () => void;
  log: (level: string, text: string) => void;
  syslog: (text: string) => void;
  invalid: () => void;
  hook: (message: BaseHookMessage) => void;
  flutter: (event: Record<string, unknown>) => void;
  crypto: (message: BaseHookMessage) => void;
  nsurl: (event: NSURLEvent) => void;
  xpc: (event: XPCSocketEvent) => void;
  jni: (event: JNIEvent) => void;
  hermes: (event: { url: string; hash: string; size: number }) => void;
  memoryScan: (event: MemoryScanEvent, data?: ArrayBuffer) => void;
  fatal: (detail: unknown) => void;
}

export interface SessionServerEvents {
  rpc: (
    mod: string,
    method: string,
    args: any[],
    ack: (err: string | null, result: any) => void,
  ) => void;
  eval: (
    source: string,
    name: string,
    ack: (err: string | null, result: any) => void,
  ) => void;
  clearLog: (
    type: "syslog" | "agent",
    ack: (err: string | null, result: any) => void,
  ) => void;
}

export type AsyncFruityRPC = RemoteRPC<FruityRPCRoute>;
export type AsyncDroidRPC = RemoteRPC<DroidRPCRoute>;

/**
 * Shared RPC surface across both platforms.
 * Only includes namespaces backed by the same @/common/* source,
 * guaranteeing identical types on both fruity and droid.
 * (flutter and fs exist on both but have platform-specific implementations)
 */
export type CommonRPC = Pick<
  AsyncFruityRPC,
  "symbol" | "memory" | "native" | "sqlite" | "script" | "syslog" | "rn"
>;

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
          (err: string | null, result: any) => {
            if (err) reject(new Error(err));
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

import type { Socket } from "socket.io";

import type { NSURLStore } from "./lib/store/nsurl.ts";
import type { HookStore } from "./lib/store/hooks.ts";
import type { CryptoStore } from "./lib/store/crypto.ts";
import type { FlutterStore } from "./lib/store/flutter.ts";
import type { JNIStore } from "./lib/store/jni.ts";
import type { XPCStore } from "./lib/store/xpc.ts";
import type { HermesStore } from "./lib/store/hermes.ts";
import type { PrivacyStore } from "./lib/store/privacy.ts";

import type { NSURLEvent } from "./lib/store/nsurl.ts";
import type { BaseMessage as BaseHookMessage } from "@agent/common/hooks/context";
import type { PrivacyMessage } from "@agent/common/hooks/privacy";
import type { JNIEvent } from "@agent/droid/hooks/jni";

export type Platform = "fruity" | "droid";
export type Mode = "app" | "daemon";

export interface SessionParams {
  platform: Platform;
  mode: Mode;
  deviceId: string;
  bundle?: string;
  pid?: number;
  name?: string;
}

export interface ServerToClientEvents {
  ready: (pid: number) => void;
  change: () => void;
  denied: () => void;
  detached: (reason: string) => void;
  log: (level: string, text: string) => void;
  syslog: (text: string) => void;
  invalid: () => void;
  lifecycle: (
    event: "inactive" | "active" | "forerground" | "background",
  ) => void;
  hook: (msg: BaseHookMessage) => void;
  flutter: (event: Record<string, unknown>) => void;
  crypto: (msg: BaseHookMessage, data?: ArrayBuffer) => void;
  nsurl: (event: NSURLEvent) => void;
  xpc: (event: Record<string, unknown>) => void;
  jni: (event: JNIEvent) => void;
  privacy: (msg: PrivacyMessage) => void;
  hermes: (event: { url: string; hash: string; size: number }) => void;
  memoryScan: (
    event: { event: string; [key: string]: unknown },
    data?: ArrayBuffer,
  ) => void;
  fatal: (detail: unknown) => void;
}

export type ClientCallback = (err: string | null, result: any) => void;

export interface ClientToServerEvents {
  rpc: (mod: string, method: string, args: any[], ack: ClientCallback) => void;
  eval: (source: string, name: string, ack: ClientCallback) => void;
  clearLog: (type: "syslog" | "agent", ack: ClientCallback) => void;
}

export interface SessionStores {
  nsurl: NSURLStore;
  hooks: HookStore;
  crypto: CryptoStore;
  flutter: FlutterStore;
  jni: JNIStore;
  xpc: XPCStore;
  hermes: HermesStore;
  privacy: PrivacyStore;
}

export type SessionSocket = Socket<ClientToServerEvents, ServerToClientEvents>;

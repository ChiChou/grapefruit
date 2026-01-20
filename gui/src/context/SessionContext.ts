import React from "react";
import { type AsyncFruityRPC, type SessionClientEvents } from "@/lib/rpc";

export const ConnectionStatus = {
  Connecting: "connecting",
  Ready: "ready",
  Disconnected: "disconnected",
} as const;

export type ConnectionStatusType =
  (typeof ConnectionStatus)[keyof typeof ConnectionStatus];

export type LoggerCallback = (level: string, message: string) => void;
export type SysLoggerCallback = (message: string) => void;

export class SessionEventEmitter {
  private handlers = new Map<string, ((...args: unknown[]) => void)[]>();

  emit<K extends keyof SessionClientEvents>(
    event: K,
    ...args: Parameters<SessionClientEvents[K]>
  ) {
    const callbacks = this.handlers.get(event as string);
    if (callbacks) {
      callbacks.forEach((cb) => cb(...args));
    }
  }

  on<K extends keyof SessionClientEvents>(
    event: K,
    callback: SessionClientEvents[K],
  ) {
    const callbacks = this.handlers.get(event as string) || [];
    callbacks.push(callback as (...args: unknown[]) => void);
    this.handlers.set(event as string, callbacks);
  }

  off<K extends keyof SessionClientEvents>(
    event: K,
    callback: SessionClientEvents[K],
  ) {
    const callbacks = this.handlers.get(event as string);
    if (!callbacks) {
      return;
    }
    const filtered = callbacks.filter(
      (cb) => cb !== (callback as (...args: unknown[]) => void),
    );

    if (filtered.length > 0) {
      this.handlers.set(event as string, filtered);
    } else {
      this.handlers.delete(event as string);
    }
  }
}

interface SessionContextType {
  device: string | undefined;
  bundle: string | undefined;
  pid: number | undefined;
  api: AsyncFruityRPC | null;
  status: ConnectionStatusType;
  events: SessionEventEmitter;
}

const defaultContext: SessionContextType = {
  device: undefined,
  bundle: undefined,
  pid: undefined,
  api: null,
  status: ConnectionStatus.Disconnected,
  events: new SessionEventEmitter(),
};

export const SessionContext = React.createContext(defaultContext);
export const useSession = () => React.useContext(SessionContext);

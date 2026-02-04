import React from "react";
import {
  type AsyncFruityRPC,
  type AsyncDroidRPC,
  type SessionClientEvents,
  type SessionServerEvents,
} from "@/lib/rpc";
import type { Socket } from "socket.io-client";

export const Status = {
  Connecting: "connecting",
  Ready: "ready",
  Disconnected: "disconnected",
} as const;

export type StatusType = (typeof Status)[keyof typeof Status];

export const Platform = {
  Fruity: "fruity",
  Droid: "droid",
} as const;

export type PlatformType = (typeof Platform)[keyof typeof Platform];

export const Mode = {
  App: "app",
  Daemon: "daemon",
} as const;

export type ModeType = (typeof Mode)[keyof typeof Mode];

export type LoggerCallback = (level: string, message: string) => void;
export type SysLoggerCallback = (message: string) => void;

interface SessionContextType {
  platform: PlatformType | undefined;
  mode: ModeType | undefined;
  device: string | undefined;
  bundle: string | undefined;
  pid: number | undefined;
  /** Typed iOS RPC API. Throws if connected to Android. */
  fruity: AsyncFruityRPC | null;
  /** Typed Android RPC API. Throws if connected to iOS. */
  droid: AsyncDroidRPC | null;
  status: StatusType;
  socket: Socket<SessionClientEvents, SessionServerEvents> | null;
}

const defaultContext: SessionContextType = {
  platform: undefined,
  mode: undefined,
  device: undefined,
  bundle: undefined,
  pid: undefined,
  fruity: null,
  droid: null,
  status: Status.Disconnected,
  socket: null,
};

export const SessionContext = React.createContext(defaultContext);
export const useSession = () => React.useContext(SessionContext);

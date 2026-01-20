import React from "react";
import {
  type AsyncFruityRPC,
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

export type LoggerCallback = (level: string, message: string) => void;
export type SysLoggerCallback = (message: string) => void;

interface SessionContextType {
  device: string | undefined;
  bundle: string | undefined;
  pid: number | undefined;
  api: AsyncFruityRPC | null;
  status: StatusType;
  socket: Socket<SessionClientEvents, SessionServerEvents> | null;
}

const defaultContext: SessionContextType = {
  device: undefined,
  bundle: undefined,
  pid: undefined,
  api: null,
  status: Status.Disconnected,
  socket: null,
};

export const SessionContext = React.createContext(defaultContext);
export const useSession = () => React.useContext(SessionContext);

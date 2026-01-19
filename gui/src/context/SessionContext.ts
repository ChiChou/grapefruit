import React from "react";
import { type AsyncFruityRPC } from "@/lib/rpc";

export const ConnectionStatus = {
  Connecting: "connecting",
  Ready: "ready",
  Disconnected: "disconnected",
} as const;

export type ConnectionStatusType =
  (typeof ConnectionStatus)[keyof typeof ConnectionStatus];

interface SessionContextType {
  device: string | undefined;
  bundle: string | undefined;
  pid: number | undefined;
  api: AsyncFruityRPC | null;
  status: ConnectionStatusType;
  syslogs: string[];
  logs: string[];
}

const defaultContext: SessionContextType = {
  device: undefined,
  bundle: undefined,
  pid: undefined,
  api: null,
  status: ConnectionStatus.Disconnected,
  syslogs: [],
  logs: [],
};

export const SessionContext = React.createContext(defaultContext);
export const useSession = () => React.useContext(SessionContext);

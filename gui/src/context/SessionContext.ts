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
  api: AsyncFruityRPC | null;
  status: ConnectionStatusType;
}

const defaultContext: SessionContextType = {
  device: undefined,
  bundle: undefined,
  api: null,
  status: ConnectionStatus.Disconnected,
};

export const SessionContext = React.createContext(defaultContext);
export const useSession = () => React.useContext(SessionContext);

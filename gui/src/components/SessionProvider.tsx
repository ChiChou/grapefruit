import { type ReactNode, useMemo, useEffect, useState } from "react";
import { Navigate, useParams } from "react-router";
import { io, Socket } from "socket.io-client";

import {
  ConnectionStatus,
  SessionContext,
  type ConnectionStatusType,
} from "@/context/SessionContext";

import {
  createAPI,
  type SessionClientEvents,
  type SessionServerEvents,
} from "@/lib/rpc";

function SessionProvider({ children }: { children: ReactNode }) {
  const { device, bundle } = useParams();
  const [status, setStatus] = useState<ConnectionStatusType>(
    ConnectionStatus.Disconnected,
  );

  const { socket, api } = useMemo(() => {
    if (!device || !bundle) {
      console.warn("Device or bundle ID missing from URL.");
      setStatus(ConnectionStatus.Disconnected);
      return { socket: null, api: null };
    }

    const newSocket: Socket<SessionClientEvents, SessionServerEvents> = io(
      "/session",
      {
        query: { device, bundle },
      },
    );

    newSocket
      .on("ready", () => {
        setStatus(ConnectionStatus.Ready);
      })
      .on("connect", () => {
        setStatus(ConnectionStatus.Connecting);
      })
      .on("disconnect", () => {
        setStatus(ConnectionStatus.Disconnected);
      });

    const newApi = createAPI(newSocket);
    setStatus(ConnectionStatus.Connecting);

    return {
      socket: newSocket,
      api: newApi,
    };
  }, [device, bundle]);

  useEffect(() => {
    return () => {
      if (status === ConnectionStatus.Ready && socket) {
        console.debug("disconnect for", bundle);
        socket.disconnect();
      }
    };
  }, [device, bundle, socket, status]);

  const contextValue = useMemo(
    () => ({
      device,
      bundle,
      api,
      status,
    }),
    [device, bundle, api, status],
  );

  if (!device || !bundle) {
    return <Navigate to="/" replace />;
  }

  return (
    <SessionContext.Provider value={contextValue}>
      {children}
    </SessionContext.Provider>
  );
}

export default SessionProvider;

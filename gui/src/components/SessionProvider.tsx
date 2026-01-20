import { type ReactNode, useMemo, useEffect, useState, useRef } from "react";
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
  const [pid, setPid] = useState<number | undefined>();

  const socketRef = useRef<Socket<
    SessionClientEvents,
    SessionServerEvents
  > | null>(null);

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

    if (socketRef.current) {
      console.debug("disconnect websocket");
      socketRef.current.disconnect();
    }
    socketRef.current = newSocket;

    newSocket
      .on("ready", (newPid: number) => {
        console.log("socket.io ready");
        setStatus(ConnectionStatus.Ready);
        setPid(newPid);
      })
      .on("log", (level: string, message: string) => {
        console.log("agent log", level, message);
      })
      .on("syslog", (message: string) => {
        console.log("syslog", message);
      })
      .on("connect", () => {
        console.debug("socket.io connect");
        setStatus(ConnectionStatus.Connecting);
      })
      .on("disconnect", () => {
        console.debug("socket.io disconnect");
        setStatus(ConnectionStatus.Disconnected);
        setPid(undefined);
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
      pid,
      api,
      status,
      socket,
    }),
    [device, bundle, pid, api, status, socket],
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

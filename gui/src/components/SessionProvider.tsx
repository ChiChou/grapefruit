import { type ReactNode, useMemo, useEffect, useState, useRef } from "react";
import { Navigate, useParams } from "react-router";
import { io, Socket } from "socket.io-client";

import {
  ConnectionStatus,
  SessionContext,
  type ConnectionStatusType,
  SessionEventEmitter,
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

  const eventEmitterRef = useRef(new SessionEventEmitter());

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
      .on("ready", (newPid: number) => {
        setStatus(ConnectionStatus.Ready);
        setPid(newPid);
        eventEmitterRef.current.emit("ready", newPid);
      })
      .on("log", (level: string, message: string) => {
        console.log("agent log", level, message);
        eventEmitterRef.current.emit("log", level, message);
      })
      .on("syslog", (message: string) => {
        console.log("syslog", message);
        eventEmitterRef.current.emit("syslog", message);
      })
      .on("connect", () => {
        setStatus(ConnectionStatus.Connecting);
      })
      .on("disconnect", () => {
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
      events: eventEmitterRef.current,
    }),
    [device, bundle, pid, api, status],
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

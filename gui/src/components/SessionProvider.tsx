import { type ReactNode, useMemo, useEffect, useState } from "react";
import { Navigate, useParams } from "react-router";
import { io, Socket } from "socket.io-client";

import {
  ConnectionStatus,
  SessionContext,
  type LogEntry,
  type ConnectionStatusType,
} from "@/context/SessionContext";

import {
  createAPI,
  type SessionClientEvents,
  type SessionServerEvents,
} from "@/lib/rpc";

const MAX_LOGS = 1024;

function SessionProvider({ children }: { children: ReactNode }) {
  const { device, bundle } = useParams();
  const [status, setStatus] = useState<ConnectionStatusType>(
    ConnectionStatus.Disconnected,
  );
  const [pid, setPid] = useState<number | undefined>();
  const [logs, setLogs] = useState<LogEntry[]>([]);
  const [syslogs, setSyslogs] = useState<LogEntry[]>([]);

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
      })
      .on("log", (level: string, message: string) => {
        console.log("agent log", level, message);
        setLogs((prevLogs) => {
          const entry: LogEntry = {
            timestamp: new Date(),
            level,
            message,
          };
          const trimmedLogs =
            prevLogs.length >= MAX_LOGS
              ? prevLogs.slice(prevLogs.length - (MAX_LOGS - 1))
              : prevLogs;

          return [...trimmedLogs, entry];
        });
      })
      .on("syslog", (message: string) => {
        console.log("syslog", message);
        setSyslogs((prevSyslogs) => {
          const entry: LogEntry = {
            timestamp: new Date(),
            level: "info",
            message,
          };
          const trimmedSyslogs =
            prevSyslogs.length >= MAX_LOGS
              ? prevSyslogs.slice(prevSyslogs.length - (MAX_LOGS - 1))
              : prevSyslogs;
          return [...trimmedSyslogs, entry];
        });
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
      logs,
      syslogs,
    }),
    [device, bundle, pid, api, status, logs, syslogs],
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

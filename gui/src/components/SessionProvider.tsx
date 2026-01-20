import { type ReactNode, useMemo, useEffect, useState } from "react";
import { Navigate, useParams } from "react-router";
import { io, Socket } from "socket.io-client";

import {
  Status,
  SessionContext,
  type StatusType,
} from "@/context/SessionContext";

import {
  createAPI,
  type SessionClientEvents,
  type SessionServerEvents,
} from "@/lib/rpc";

function SessionProvider({ children }: { children: ReactNode }) {
  const { device, bundle } = useParams();
  const [status, setStatus] = useState<StatusType>(Status.Disconnected);
  const [pid, setPid] = useState<number | undefined>();

  const { socket, api } = useMemo(() => {
    if (!device || !bundle) {
      console.warn("Device or bundle ID missing from URL.");
      setStatus(Status.Disconnected);
      return { socket: null, api: null };
    }

    const socket: Socket<SessionClientEvents, SessionServerEvents> = io(
      "/session",
      {
        query: { device, bundle },
      },
    );

    socket
      .on("ready", (newPid: number) => {
        console.log("socket.io ready");
        setStatus(Status.Ready);
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
        setStatus(Status.Connecting);
      })
      .on("disconnect", () => {
        console.debug("socket.io disconnect");
        setStatus(Status.Disconnected);
        setPid(undefined);
      });

    const api = createAPI(socket);
    setStatus(Status.Connecting);

    return {
      socket,
      api,
    };
  }, [device, bundle]);

  useEffect(() => {
    return () => {
      if (status === Status.Ready && socket) {
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

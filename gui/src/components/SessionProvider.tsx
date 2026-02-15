import { type ReactNode, useMemo, useEffect, useRef, useState } from "react";
import { Navigate, useParams, useSearchParams } from "react-router";
import { io, Socket } from "socket.io-client";

import {
  Status,
  Mode,
  Platform,
  SessionContext,
  type StatusType,
  type PlatformType,
  type ModeType,
  type FlutterRuntimeInfo,
} from "@/context/SessionContext";

import {
  createAPI,
  type SessionClientEvents,
  type SessionServerEvents,
} from "@/lib/rpc";

function fnv1a(input: string): string {
  let hash = 0x811c9dc5;
  for (let i = 0; i < input.length; i++) {
    hash ^= input.charCodeAt(i);
    hash = (hash * 0x01000193) >>> 0;
  }
  return hash.toString(16).padStart(8, "0");
}

function SessionProvider({ children }: { children: ReactNode }) {
  const params = useParams();
  const [searchParams] = useSearchParams();

  // Extract platform, mode, device from route params
  const platform = params.platform as PlatformType | undefined;
  const mode = params.mode as ModeType | undefined;
  const device = params.device;

  // For app mode, use bundle; for daemon mode, use pid from URL
  const bundle = mode === Mode.App ? params.target : undefined;
  const targetPid = mode === Mode.Daemon ? parseInt(params.target || "0", 10) : undefined;
  const processName = mode === Mode.Daemon ? (searchParams.get("name") ?? undefined) : undefined;

  const [status, setStatus] = useState<StatusType>(Status.Disconnected);
  const [pid, setPid] = useState<number | undefined>(targetPid);
  const [flutterRuntime, setFlutterRuntime] = useState<FlutterRuntimeInfo | null>(null);
  const detectKeyRef = useRef<string | null>(null);

  // Compute project identifier matching server-side logic
  const identifier = useMemo(() => {
    if (mode === Mode.App && bundle) return bundle;
    if (mode === Mode.Daemon && targetPid) {
      const pname = processName || "pid";
      return `${pname}-${fnv1a(pname + targetPid)}`;
    }
    return undefined;
  }, [mode, bundle, targetPid, processName]);

  const { socket, fruity, droid } = useMemo(() => {
    if (!device || !platform || !mode) {
      console.warn("Device, platform, or mode missing from URL.");
      setStatus(Status.Disconnected);
      return { socket: null, fruity: null, droid: null };
    }

    // Build query params based on mode
    const query: Record<string, string> = { device, platform, mode };
    if (mode === Mode.App && bundle) {
      query.bundle = bundle;
    } else if (mode === Mode.Daemon && targetPid) {
      query.pid = String(targetPid);
      if (processName) query.name = processName;
    }

    const socket: Socket<SessionClientEvents, SessionServerEvents> = io(
      "/session",
      { query },
    );

    socket
      .on("invalid", () => {
        // bug workaround: first time connection
        // the server receives empty query
        location.reload();
      })
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
        if (mode === Mode.App) {
          setPid(undefined);
        }
      });

    const { fruity, droid } = createAPI(socket, platform);
    setStatus(Status.Connecting);

    return { socket, fruity, droid };
  }, [device, platform, mode, bundle, targetPid, processName]);

  useEffect(() => {
    setFlutterRuntime(null);
    detectKeyRef.current = null;
  }, [platform, mode, device, bundle, pid]);

  useEffect(() => {
    if (status !== Status.Ready || !platform) return;

    const sessionKey = `${platform}:${device}:${mode}:${bundle ?? pid ?? "unknown"}`;
    if (detectKeyRef.current === sessionKey) return;
    detectKeyRef.current = sessionKey;

    const runtimeApi = platform === Platform.Fruity ? fruity : droid;
    if (!runtimeApi) return;

    runtimeApi.flutter
      .detect()
      .then((result) => {
        setFlutterRuntime(result as FlutterRuntimeInfo);
      })
      .catch((error) => {
        console.warn("flutter.detect failed:", error);
        setFlutterRuntime({
          isFlutter: false,
          platform: platform === Platform.Fruity ? "ios" : "android",
          engineModule: null,
          appModule: null,
          hints: ["flutter.detect() failed"],
        });
      });
  }, [status, platform, device, mode, bundle, pid, fruity, droid]);

  useEffect(() => {
    return () => {
      if (status === Status.Ready && socket) {
        console.debug("disconnect for", bundle || targetPid);
        socket.disconnect();
      }
    };
  }, [device, platform, mode, bundle, targetPid, processName, socket, status]);

  const contextValue = useMemo(
    () => ({
      platform,
      mode,
      device,
      bundle,
      pid,
      identifier,
      fruity,
      droid,
      status,
      socket,
      flutterRuntime,
    }),
    [
      platform,
      mode,
      device,
      bundle,
      pid,
      identifier,
      fruity,
      droid,
      status,
      socket,
      flutterRuntime,
    ],
  );

  // Validate required params
  if (!device || !platform || !mode) {
    return <Navigate to="/" replace />;
  }

  // For app mode, bundle is required
  if (mode === Mode.App && !bundle) {
    return <Navigate to="/" replace />;
  }

  // For daemon mode, pid is required
  if (mode === Mode.Daemon && !targetPid) {
    return <Navigate to="/" replace />;
  }

  return (
    <SessionContext.Provider value={contextValue}>
      {children}
    </SessionContext.Provider>
  );
}

export default SessionProvider;

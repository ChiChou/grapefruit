import { useCallback, useEffect, useRef, useState } from "react";
import { io, type Socket } from "socket.io-client";
import { useSession } from "@/context/SessionContext";
import { usePlatformQuery } from "@/lib/queries";

interface ProcessInfo {
  platform: string;
  arch: string;
  pointerSize: number;
  pageSize: number;
}

export interface CmdOptions {
  output?: "plain" | "html";
}

function socketCmd(
  socket: Socket,
  event: string,
  ...args: any[]
): Promise<any> {
  return new Promise((resolve, reject) => {
    socket.emit(event, ...args, (err: string | null, result?: any) => {
      if (err) reject(new Error(err));
      else resolve(result);
    });
  });
}

interface R2SessionHandle {
  cmd: (command: string, options?: CmdOptions) => Promise<string>;
  analyze: (address: string) => Promise<any>;
  disassemble: (address: string, options?: CmdOptions) => Promise<string | null>;
  graph: (address: string) => Promise<any>;
  isReady: boolean;
  error: string | null;
}

export function useR2Session(): R2SessionHandle {
  const { device, pid, platform } = useSession();
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const socketRef = useRef<Socket | null>(null);

  const { data: processInfo } = usePlatformQuery<ProcessInfo>(
    ["processInfo"],
    (api) => api.info.processInfo(),
  );

  useEffect(() => {
    if (!device || !pid || !processInfo) return;

    const socket = io("/r2", { autoConnect: true });
    socketRef.current = socket;

    socket.on("connect", async () => {
      try {
        await socketCmd(socket, "open", {
          deviceId: device,
          pid,
          arch: processInfo.arch,
          platform: processInfo.platform,
          pointerSize: processInfo.pointerSize,
          pageSize: processInfo.pageSize,
        });
        setIsReady(true);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    });

    socket.on("connect_error", (e) => {
      setError(e.message);
    });

    return () => {
      socket.disconnect();
      socketRef.current = null;
      setIsReady(false);
    };
  }, [device, pid, platform, processInfo]);

  const cmd = useCallback(
    async (command: string, options?: CmdOptions): Promise<string> => {
      if (!socketRef.current) throw new Error("R2 session not ready");
      return socketCmd(socketRef.current, "cmd", command, options?.output ?? null);
    },
    [],
  );

  const analyze = useCallback(
    async (address: string) => {
      const raw = await cmd(`s ${address}; af; afbj`);
      return JSON.parse(raw);
    },
    [cmd],
  );

  const disassemble = useCallback(
    async (address: string, options?: CmdOptions): Promise<string | null> => {
      if (!socketRef.current) throw new Error("R2 session not ready");
      return socketCmd(socketRef.current, "disassemble", address, options?.output ?? null);
    },
    [],
  );

  const graph = useCallback(
    async (address: string) => {
      if (!socketRef.current) throw new Error("R2 session not ready");
      return socketCmd(socketRef.current, "graph", address) ?? null;
    },
    [],
  );

  return { cmd, analyze, disassemble, graph, isReady, error };
}

import { useCallback, useEffect, useRef, useState } from "react";
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
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [isReady, setIsReady] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const opening = useRef(false);
  const sessionRef = useRef<string | null>(null);

  const { data: processInfo } = usePlatformQuery<ProcessInfo>(
    ["processInfo"],
    (api) => api.info.processInfo(),
  );

  useEffect(() => {
    if (!device || !pid || !processInfo || opening.current) return;
    opening.current = true;

    fetch("/api/r2/open", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        deviceId: device,
        pid,
        arch: processInfo.arch,
        platform: processInfo.platform,
        pointerSize: processInfo.pointerSize,
        pageSize: processInfo.pageSize,
      }),
    })
      .then((res) => res.json())
      .then((data: { id?: string; error?: string }) => {
        if (data.error) {
          setError(data.error);
          return;
        }
        sessionRef.current = data.id!;
        setSessionId(data.id!);
        setIsReady(true);
      })
      .catch((e) => setError(e.message))
      .finally(() => { opening.current = false; });

    return () => {
      const id = sessionRef.current;
      if (id) {
        fetch(`/api/r2/${id}`, { method: "DELETE" }).catch(() => {});
        sessionRef.current = null;
      }
    };
  }, [device, pid, platform, processInfo]);

  const cmd = useCallback(
    async (command: string, options?: CmdOptions): Promise<string> => {
      if (!sessionId) throw new Error("R2 session not ready");
      const res = await fetch(`/api/r2/${sessionId}/cmd`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ command, output: options?.output }),
      });
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      return data.result;
    },
    [sessionId],
  );

  const analyze = useCallback(
    async (address: string) => {
      if (!sessionId) throw new Error("R2 session not ready");
      const res = await fetch(`/api/r2/${sessionId}/analyze/${address}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      return data.blocks;
    },
    [sessionId],
  );

  const disassemble = useCallback(
    async (address: string, options?: CmdOptions): Promise<string | null> => {
      if (!sessionId) throw new Error("R2 session not ready");
      const output = options?.output ?? "plain";
      const res = await fetch(
        `/api/r2/${sessionId}/disassemble/${address}?output=${output}`,
      );
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      return data.text;
    },
    [sessionId],
  );

  const graph = useCallback(
    async (address: string) => {
      if (!sessionId) throw new Error("R2 session not ready");
      const res = await fetch(`/api/r2/${sessionId}/graph/${address}`);
      const data = await res.json();
      if (data.error) throw new Error(data.error);
      return data.cfg;
    },
    [sessionId],
  );

  return { cmd, analyze, disassemble, graph, isReady, error };
}

import { useEffect, useRef, useState } from "react";
import { t } from "i18next";
import { FileText, Webhook, Activity } from "lucide-react";
import { clsx } from "clsx";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ScrollArea } from "@/components/ui/scroll-area";
import type { LogEntry } from "@/context/SessionContext";
import { ConnectionStatus, useSession } from "@/context/SessionContext";

function useLogThrottle(logs: LogEntry[], delay: number = 100) {
  const [throttledLogs, setThrottledLogs] = useState<LogEntry[]>([]);
  const lastUpdateRef = useRef(0);
  const pendingRef = useRef<LogEntry[]>([]);

  useEffect(() => {
    const now = Date.now();
    const elapsed = now - lastUpdateRef.current;

    if (elapsed >= delay) {
      setThrottledLogs((prev) => [...prev, ...pendingRef.current]);
      pendingRef.current = [];
      lastUpdateRef.current = now;
    } else {
      pendingRef.current.push(...logs);
    }
  }, [logs, delay]);

  return throttledLogs;
}

const levelColors: Record<string, string> = {
  error: "text-red-500",
  warn: "text-yellow-500",
  info: "text-green-500",
  debug: "text-blue-500",
  trace: "text-gray-500",
};

export function BottomPanelView() {
  const { api, status, syslogs, logs } = useSession();
  const throttledLogs = useLogThrottle(syslogs);
  const throttledAgentLogs = useLogThrottle(logs);
  const scrollRef = useRef<HTMLDivElement>(null);
  const agentScrollRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (api && status === ConnectionStatus.Ready) api.syslog.start();

    return () => {
      if (api) api.syslog.stop();
    };
  }, [api, status]);

  useEffect(() => {
    if (scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight;
    }
  }, [throttledLogs]);

  useEffect(() => {
    if (agentScrollRef.current) {
      agentScrollRef.current.scrollTop = agentScrollRef.current.scrollHeight;
    }
  }, [throttledAgentLogs]);

  return (
    <Tabs defaultValue="logs" className="h-full flex flex-col">
      <TabsList className="w-full justify-start rounded-none border-b bg-transparent p-0">
        <TabsTrigger
          value="logs"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <FileText className="h-4 w-4" />
          {t("logs")}
        </TabsTrigger>
        <TabsTrigger
          value="hooks"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Webhook className="h-4 w-4" />
          {t("hooks")}
        </TabsTrigger>
        <TabsTrigger
          value="agent-logs"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Activity className="h-4 w-4" />
          {t("agent_logs")}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="logs" className="flex-1 overflow-hidden mt-0">
        <ScrollArea className="h-full">
          <div
            ref={scrollRef}
            className="h-full max-h-[calc(100vh-300px)] space-y-1 p-4 font-mono text-xs"
          >
            {throttledLogs.map((log, i) => (
              <div key={i} className="flex gap-2">
                <span className="text-muted-foreground shrink-0">
                  {log.timestamp.toLocaleTimeString()}
                </span>
                <span
                  className={clsx(
                    "shrink-0 font-bold w-10",
                    levelColors[log.level] || "text-gray-500",
                  )}
                >
                  {log.level.toUpperCase().slice(0, 5)}
                </span>
                <span className="whitespace-pre-wrap break-all">
                  {log.message}
                </span>
              </div>
            ))}
          </div>
        </ScrollArea>
      </TabsContent>
      <TabsContent value="hooks" className="flex-1 p-4 mt-0"></TabsContent>
      <TabsContent value="agent-logs" className="flex-1 overflow-hidden mt-0">
        <ScrollArea className="h-full">
          <div
            ref={agentScrollRef}
            className="h-full max-h-[calc(100vh-300px)] space-y-1 p-4 font-mono text-xs"
          >
            {throttledAgentLogs.map((log, i) => (
              <div key={i} className="flex gap-2">
                <span className="text-muted-foreground shrink-0">
                  {log.timestamp.toLocaleTimeString()}
                </span>
                <span
                  className={clsx(
                    "shrink-0 font-bold w-10",
                    levelColors[log.level] || "text-gray-500",
                  )}
                >
                  {log.level.toUpperCase().slice(0, 5)}
                </span>
                <span className="whitespace-pre-wrap break-all">
                  {log.message}
                </span>
              </div>
            ))}
          </div>
        </ScrollArea>
      </TabsContent>
    </Tabs>
  );
}

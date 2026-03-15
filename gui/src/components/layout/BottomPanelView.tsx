import { useEffect, useState, useRef } from "react";
import { t } from "i18next";
import { useQuery } from "@tanstack/react-query";
import {
  FileText,
  Activity,
  Anchor,
  Terminal,
} from "lucide-react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Status, Platform, useSession } from "@/context/SessionContext";

import { LogPanel, type LogViewerHandle } from "../shared/LogPanel";
import { HookResultsView } from "../shared/HookResultsView";
import { CodeScratchPadTab } from "../tabs/CodeScratchPadTab";

const BOTTOM_PANEL_TAB_STATE = "BOTTOM_PANEL_TAB_STATE";

export function BottomPanelView() {
  const { fruity, droid, platform, status, socket, device, identifier } =
    useSession();
  const [activeTab, setActiveTab] = useState<string>(() => {
    try {
      return localStorage.getItem(BOTTOM_PANEL_TAB_STATE) || "logs";
    } catch {
      return "logs";
    }
  });

  const syslogRef = useRef<LogViewerHandle>(null);
  const logRef = useRef<LogViewerHandle>(null);


  const { data: syslogHistory } = useQuery<string>({
    queryKey: ["logHistory", device, identifier, "syslog"],
    queryFn: async () => {
      const res = await fetch(
        `/api/logs/${device}/${identifier}/syslog?limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load syslog history");
      return res.text();
    },
    enabled: !!device && !!identifier,
    staleTime: Infinity,
    gcTime: 0,
  });

  const { data: agentLogHistory } = useQuery<string>({
    queryKey: ["logHistory", device, identifier, "agent"],
    queryFn: async () => {
      const res = await fetch(
        `/api/logs/${device}/${identifier}/agent?limit=5000`,
      );
      if (!res.ok) throw new Error("Failed to load agent log history");
      return res.text();
    },
    enabled: !!device && !!identifier,
    staleTime: Infinity,
    gcTime: 0,
  });

  useEffect(() => {
    if (syslogHistory && syslogHistory.length > 0) {
      syslogRef.current?.append(syslogHistory);
    }
  }, [syslogHistory]);

  useEffect(() => {
    if (agentLogHistory && agentLogHistory.length > 0) {
      logRef.current?.append(agentLogHistory);
    }
  }, [agentLogHistory]);

  useEffect(() => {
    const syslogApi = platform === Platform.Droid ? droid : fruity;
    syslogApi?.syslog.start();

    return () => {
      syslogApi?.syslog.stop();
    };
  }, [fruity, droid, platform, status, socket]);

  useEffect(() => {
    const handleSyslog = (message: string) => {
      syslogRef.current?.append(message);
    };
    const handleLog = (level: string, message: string) => {
      logRef.current?.append(`[${level}] ${message}`);
    };

    if (status === Status.Ready && socket) {
      socket.on("syslog", handleSyslog);
      socket.on("log", handleLog);
    }

    return () => {
      if (socket) {
        socket.off("syslog", handleSyslog);
        socket.off("log", handleLog);
      }
    };
  }, [socket, status]);

  useEffect(() => {
    localStorage.setItem(BOTTOM_PANEL_TAB_STATE, activeTab);
  }, [activeTab]);

  // Listen for REPL content additions to auto-switch to REPL tab
  useEffect(() => {
    const handleReplContentAdded = () => {
      setActiveTab("repl");
    };

    window.addEventListener("repl:content-added", handleReplContentAdded);
    return () => {
      window.removeEventListener("repl:content-added", handleReplContentAdded);
    };
  }, []);

  return (
    <Tabs
      value={activeTab}
      onValueChange={setActiveTab}
      className="h-full flex flex-col"
    >
      <TabsList className="w-full justify-start rounded-none border-b bg-transparent p-0">
        <TabsTrigger
          value="logs"
          className="rounded-none border-b-2 border-transparent data-active:border-primary flex items-center gap-2"
        >
          <FileText className="h-4 w-4" />
          {t("logs")}
        </TabsTrigger>
        <TabsTrigger
          value="hooks"
          className="rounded-none border-b-2 border-transparent data-active:border-primary flex items-center gap-2"
        >
          <Anchor className="h-4 w-4" />
          {t("hook_logs")}
        </TabsTrigger>
        <TabsTrigger
          value="agent-logs"
          className="rounded-none border-b-2 border-transparent data-active:border-primary flex items-center gap-2"
        >
          <Activity className="h-4 w-4" />
          {t("agent_logs")}
        </TabsTrigger>
        <TabsTrigger
          value="repl"
          className="rounded-none border-b-2 border-transparent data-active:border-primary flex items-center gap-2"
        >
          <Terminal className="h-4 w-4" />
          {t("code_scratch_pad")}
        </TabsTrigger>
      </TabsList>
      <TabsContent
        value="logs"
        className="flex-1 overflow-hidden mt-0"
        keepMounted
        hidden={activeTab !== "logs"}
      >
        <LogPanel
          ref={syslogRef}
          downloadUrl={`/api/logs/${device}/${identifier}/syslog?download=1`}
          onClear={() => socket?.emit("clearLog", "syslog", () => {})}
        />
      </TabsContent>
      <TabsContent
        value="hooks"
        className="flex-1 overflow-hidden mt-0"
        keepMounted
        hidden={activeTab !== "hooks"}
      >
        <HookResultsView />
      </TabsContent>
      <TabsContent
        value="agent-logs"
        className="flex-1 overflow-hidden mt-0"
        keepMounted
        hidden={activeTab !== "agent-logs"}
      >
        <LogPanel
          ref={logRef}
          downloadUrl={`/api/logs/${device}/${identifier}/agent?download=1`}
          onClear={() => socket?.emit("clearLog", "agent", () => {})}
        />
      </TabsContent>
      <TabsContent
        value="repl"
        className="flex-1 overflow-hidden mt-0"
        keepMounted
        hidden={activeTab !== "repl"}
      >
        <CodeScratchPadTab />
      </TabsContent>
    </Tabs>
  );
}

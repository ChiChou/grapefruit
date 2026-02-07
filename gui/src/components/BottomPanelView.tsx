import { useEffect, useState, useRef } from "react";
import { t } from "i18next";
import { FileText, Activity, Anchor, Terminal } from "lucide-react";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Status, Mode, Platform, useSession } from "@/context/SessionContext";

import { LogViewer, type LogViewerHandle } from "./LogViewer";
import { HookResultsView } from "./HookResultsView";
import { CodeEditorTab } from "./tabs/CodeEditorTab";

const BOTTOM_PANEL_TAB_STATE = "BOTTOM_PANEL_TAB_STATE";

export function BottomPanelView() {
  const { fruity, droid, platform, status, socket, device, bundle, pid, mode } = useSession();
  const [activeTab, setActiveTab] = useState<string>(() => {
    try {
      return localStorage.getItem(BOTTOM_PANEL_TAB_STATE) || "logs";
    } catch {
      return "logs";
    }
  });

  const syslogRef = useRef<LogViewerHandle>(null);
  const logRef = useRef<LogViewerHandle>(null);
  const historyLoadedRef = useRef(false);

  // Load historical logs on initialization
  useEffect(() => {
    if (!device || historyLoadedRef.current) return;

    const identifier = mode === Mode.App ? bundle : `pid-${pid}`;
    if (!identifier) return;

    historyLoadedRef.current = true;

    const loadLogs = async (
      type: "syslog" | "agent",
      ref: React.RefObject<LogViewerHandle | null>,
    ) => {
      try {
        const res = await fetch(
          `/api/logs/${device}/${identifier}/${type}?limit=5000`,
        );
        if (res.ok) {
          const text = await res.text();
          if (text.length > 0) {
            ref.current?.append(text);
          }
        }
      } catch (e) {
        console.error(`Failed to load ${type} history:`, e);
      }
    };

    loadLogs("syslog", syslogRef);
    loadLogs("agent", logRef);
  }, [device, bundle, pid, mode]);

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
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <FileText className="h-4 w-4" />
          {t("logs")}
        </TabsTrigger>
        <TabsTrigger
          value="hooks"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Anchor className="h-4 w-4" />
          {t("hooks")}
        </TabsTrigger>
        <TabsTrigger
          value="agent-logs"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Activity className="h-4 w-4" />
          {t("agent_logs")}
        </TabsTrigger>
        <TabsTrigger
          value="repl"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Terminal className="h-4 w-4" />
          {t("code_editor")}
        </TabsTrigger>
      </TabsList>
      <TabsContent
        value="logs"
        className="flex-1 overflow-hidden mt-0"
        forceMount
        hidden={activeTab !== "logs"}
      >
        <LogViewer ref={syslogRef} />
      </TabsContent>
      <TabsContent
        value="hooks"
        className="flex-1 overflow-hidden mt-0"
        forceMount
        hidden={activeTab !== "hooks"}
      >
        <HookResultsView />
      </TabsContent>
      <TabsContent
        value="agent-logs"
        className="flex-1 overflow-hidden mt-0"
        forceMount
        hidden={activeTab !== "agent-logs"}
      >
        <LogViewer ref={logRef} />
      </TabsContent>
      <TabsContent
        value="repl"
        className="flex-1 overflow-hidden mt-0"
        forceMount
        hidden={activeTab !== "repl"}
      >
        <CodeEditorTab />
      </TabsContent>
    </Tabs>
  );
}

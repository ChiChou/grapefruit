import { useEffect, useState, useRef } from "react";
import { t } from "i18next";
import { FileText, Activity, Earth } from "lucide-react";
import { Terminal as XTerm } from "@xterm/xterm";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Status, useSession } from "@/context/SessionContext";

import { Terminal } from "./Terminal";
import { GeoHookView } from "./views/GeoHookView";

const BOTTOM_PANEL_TAB_STATE = "BOTTOM_PANEL_TAB_STATE";

export function BottomPanelView() {
  const { fruity, status, socket } = useSession();
  const [activeTab, setActiveTab] = useState<string>(() => {
    try {
      return localStorage.getItem(BOTTOM_PANEL_TAB_STATE) || "logs";
    } catch {
      return "logs";
    }
  });

  const syslogTerminalRef = useRef<XTerm | null>(null);
  const logTerminalRef = useRef<XTerm | null>(null);

  useEffect(() => {
    fruity?.syslog.start();

    return () => {
      fruity?.syslog.stop();
    };
  }, [fruity, status, socket]);

  useEffect(() => {
    const handleSyslog = (message: string) => {
      syslogTerminalRef.current?.writeln(message);
    };
    const handleLog = (level: string, message: string) => {
      logTerminalRef.current?.writeln(`[${level}] ${message}`);
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
        {/*<TabsTrigger
          value="hooks"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Webhook className="h-4 w-4" />
          {t("hooks")}
        </TabsTrigger>*/}
        <TabsTrigger
          value="agent-logs"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Activity className="h-4 w-4" />
          {t("agent_logs")}
        </TabsTrigger>
        <TabsTrigger
          value="geolocation"
          className="rounded-none border-b-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
        >
          <Earth className="h-4 w-4" />
          {t("geolocation_simulation")}
        </TabsTrigger>
      </TabsList>
      <TabsContent value="logs" className="flex-1 overflow-hidden mt-0">
        <Terminal
          onTerminalReady={(term) => (syslogTerminalRef.current = term)}
        />
      </TabsContent>
      <TabsContent value="agent-logs" className="flex-1 overflow-hidden mt-0">
        <Terminal onTerminalReady={(term) => (logTerminalRef.current = term)} />
      </TabsContent>
      <TabsContent value="geolocation" className="flex-1 p-4 mt-0">
        <GeoHookView />
      </TabsContent>
    </Tabs>
  );
}

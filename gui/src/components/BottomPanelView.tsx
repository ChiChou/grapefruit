import { useEffect, useRef } from "react";
import { t } from "i18next";
import { FileText, Activity } from "lucide-react";
import { Terminal as XTerm } from "@xterm/xterm";

import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { Terminal } from "./Terminal";

export function BottomPanelView() {
  const { api, status, events } = useSession();

  const syslogTerminalRef = useRef<XTerm | null>(null);
  const logTerminalRef = useRef<XTerm | null>(null);

  useEffect(() => {
    if (api && status === ConnectionStatus.Ready) api.syslog.start();
  }, [api, status]);

  useEffect(() => {
    if (api && status === ConnectionStatus.Ready) {
      const handleSyslog = (message: string) => {
        syslogTerminalRef.current?.writeln(message);
      };
      const handleLog = (level: string, message: string) => {
        logTerminalRef.current?.writeln(`[${level}] ${message}`);
      };

      events.on("syslog", handleSyslog);
      events.on("log", handleLog);

      return () => {
        events.off("syslog", handleSyslog);
        events.off("log", handleLog);
        if (status === ConnectionStatus.Ready) {
          api.syslog.stop();
        }
      };
    }
  }, [api, status, events]);

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
      </TabsList>
      <TabsContent value="logs" className="flex-1 overflow-hidden mt-0">
        <Terminal onTerminalReady={(term) => (syslogTerminalRef.current = term)} />
      </TabsContent>
      {/*<TabsContent value="hooks" className="flex-1 p-4 mt-0"></TabsContent>*/}
      <TabsContent value="agent-logs" className="flex-1 overflow-hidden mt-0">
        <Terminal onTerminalReady={(term) => (logTerminalRef.current = term)} />
      </TabsContent>
    </Tabs>
  );
}

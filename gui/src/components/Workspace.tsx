import { useEffect, useState } from "react";
import { Navigate, useParams } from "react-router";
import { t } from "i18next";
import { FileText, Terminal, Webhook } from "lucide-react";
import io from "socket.io-client";

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";

import createRPC from "@/lib/rpc";
import { LeftPanelView } from "./LeftPanelView";

const ConnectionStatus = {
  Connecting: "connecting",
  Ready: "ready",
  Disconnected: "disconnected",
} as const;

type ConnectionStatus =
  (typeof ConnectionStatus)[keyof typeof ConnectionStatus];

export function Workspace() {
  const { device, bundle } = useParams();

  const [status, setStatus] = useState<ConnectionStatus>(
    ConnectionStatus.Connecting,
  );
  const [leftPanelSize, setLeftPanelSize] = useState<number>(() => {
    const saved = localStorage.getItem("workspace-left-panel-size");
    return saved ? Number(saved) : 20;
  });
  const [bottomPanelSize, setBottomPanelSize] = useState<number>(() => {
    const saved = localStorage.getItem("workspace-bottom-panel-size");
    return saved ? Number(saved) : 30;
  });

  useEffect(() => {
    const socket = io(`/session`, {
      query: { device, bundle },
    });

    const rpc = createRPC(socket);

    socket.on("connect", () => {
      console.log("Connected to workspace events socket");
      setStatus(ConnectionStatus.Connecting);
    });

    socket.on("disconnect", () => {
      console.log("Disconnected from workspace events socket");
      setStatus(ConnectionStatus.Disconnected);
    });

    socket.on("ready", async () => {
      setStatus(ConnectionStatus.Ready);
      // test call
      console.info(await rpc.lsof.fds());
      const xml = await rpc.entitlements.xml();
      console.info(xml);
    });

    return () => {
      socket.disconnect();
    };
  }, [device, bundle]);

  if (!device || !bundle) {
    return <Navigate to="/" replace />;
  }

  const handleLeftPanelResize = (sizes: number[]) => {
    const size = sizes[0];
    setLeftPanelSize(size);
    localStorage.setItem("workspace-left-panel-size", String(size));
  };

  const handleBottomPanelResize = (sizes: number[]) => {
    const size = sizes[1];
    setBottomPanelSize(size);
    localStorage.setItem("workspace-bottom-panel-size", String(size));
  };

  const getStatusColor = () => {
    switch (status) {
      case ConnectionStatus.Ready:
        return "bg-green-500";
      case ConnectionStatus.Disconnected:
        return "bg-orange-500";
      case ConnectionStatus.Connecting:
      default:
        return "bg-gray-600";
    }
  };

  return (
    <div className="flex h-screen flex-col">
      <ResizablePanelGroup
        direction="horizontal"
        className="h-full"
        onLayout={handleLeftPanelResize}
      >
        <ResizablePanel
          defaultSize={leftPanelSize}
          minSize={15}
          className="flex flex-col"
        >
          <LeftPanelView device={device} bundle={bundle} />
        </ResizablePanel>
        <ResizableHandle withHandle />
        <ResizablePanel>
          <ResizablePanelGroup
            direction="vertical"
            className="h-full"
            onLayout={handleBottomPanelResize}
          >
            <ResizablePanel>
              {/* todo: use this area for document tabs */}
            </ResizablePanel>
            <ResizableHandle />
            <ResizablePanel defaultSize={bottomPanelSize}>
              <Tabs defaultValue="logs" className="h-full flex flex-col">
                <TabsList className="w-full justify-start rounded-none border-b bg-transparent p-0">
                  <TabsTrigger
                    value="logs"
                    className="rounded-none border-1-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
                  >
                    <FileText className="h-4 w-4" />
                    {t("logs")}
                  </TabsTrigger>
                  <TabsTrigger
                    value="shell"
                    className="rounded-none border-1-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
                  >
                    <Terminal className="h-4 w-4" />
                    {t("shell")}
                  </TabsTrigger>
                  <TabsTrigger
                    value="hooks"
                    className="rounded-none border-1-2 border-transparent data-[state=active]:border-primary flex items-center gap-2"
                  >
                    <Webhook className="h-4 w-4" />
                    {t("hooks")}
                  </TabsTrigger>
                </TabsList>
                <TabsContent value="logs" className="flex-1 p-4"></TabsContent>
                <TabsContent value="shell" className="flex-1 p-4"></TabsContent>
                <TabsContent value="hooks" className="flex-1 p-4"></TabsContent>
              </Tabs>
            </ResizablePanel>
          </ResizablePanelGroup>
        </ResizablePanel>
      </ResizablePanelGroup>
      <footer className={`${getStatusColor()} px-4 py-1 text-xs text-white`}>
        {status === ConnectionStatus.Ready && t("connected")}
        {status === ConnectionStatus.Connecting && t("connecting")}
        {status === ConnectionStatus.Disconnected && t("disconnected")}
      </footer>
    </div>
  );
}

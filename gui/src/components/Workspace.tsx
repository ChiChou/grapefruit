import { useEffect, useState } from "react";
import { t } from "i18next";

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import { LeftPanelView } from "./LeftPanelView";
import { BottomPanelView } from "./BottomPanelView";
import { ConnectionStatus, useSession } from "@/context/SessionContext";
import SessionProvider from "./SessionProvider";

function WorkspaceContent() {
  const { api, status } = useSession();
  const [leftPanelSize, setLeftPanelSize] = useState<number>(() => {
    const saved = localStorage.getItem("workspace-left-panel-size");
    return saved ? Number(saved) : 20;
  });
  const [bottomPanelSize, setBottomPanelSize] = useState<number>(() => {
    const saved = localStorage.getItem("workspace-bottom-panel-size");
    return saved ? Number(saved) : 30;
  });

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

  useEffect(() => {
    if (!api || status !== ConnectionStatus.Ready) return;

    api.lsof.fds().then(console.log);
    api.fs
      .ls("!")
      .then((files) => {
        console.log("Root files:", files);
      })
      .catch(console.error);
  }, [status, api]);

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
          <LeftPanelView />
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
              <BottomPanelView />
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

export function Workspace() {
  return (
    <SessionProvider>
      <WorkspaceContent />
    </SessionProvider>
  );
}

import { useEffect, useMemo, useState } from "react";
import { t } from "i18next";

import {
  type DockviewApi,
  DockviewReact,
  type DockviewReadyEvent,
  type SerializedDockview,
  themeLight,
} from "dockview";

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import { LeftPanelView } from "./LeftPanelView";
import { BottomPanelView } from "./BottomPanelView";
import { ConnectionStatus, useSession } from "@/context/SessionContext";
import SessionProvider from "./SessionProvider";
import { useTheme } from "./theme-provider";
import { HandlesTab } from "./tabs/HandlesTab";
import { InfoPlistTab } from "./tabs/InfoPlistTab";
import { ModuleDetailTab } from "./tabs/ModuleDetailTab";
import { DockContext, useDockActions } from "@/context/DockContext";

function WorkspaceContent() {
  const { status } = useSession();
  const { theme } = useTheme();
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

  const [dockViewClazz, setDockViewClazz] = useState<string>(
    "dockview-theme-light",
  );

  useEffect(() => {
    setDockViewClazz(
      theme === "dark" ? "dockview-theme-abyss" : "dockview-theme-light",
    );
  }, [theme]);

  const [dockApi, setDockApi] = useState<DockviewApi | null>(null);
  const { openSingletonPanel, openFilePanel } = useDockActions(dockApi);

  const dockContextValue = useMemo(
    () => ({
      api: dockApi,
      openSingletonPanel,
      openFilePanel,
    }),
    [dockApi, openSingletonPanel, openFilePanel],
  );

  const components = {
    handles: HandlesTab,
    infoPlist: InfoPlistTab,
    moduleDetail: ModuleDetailTab,
  };

  const onReady = (event: DockviewReadyEvent) => {
    setDockApi(event.api);

    const savedLayout = localStorage.getItem("workspace-dockview-layout");
    if (savedLayout) {
      try {
        const layout: SerializedDockview = JSON.parse(savedLayout);
        event.api.fromJSON(layout);
      } catch (e) {
        console.error("Failed to restore dockview layout:", e);
        localStorage.removeItem("workspace-dockview-layout");
        // Create default layout on restore failure
        createDefaultLayout(event.api);
      }
    } else {
      // Default layout if no saved layout exists
      createDefaultLayout(event.api);
    }

    // Save layout on changes - use event.api directly to avoid stale closure
    event.api.onDidLayoutChange(() => {
      const layout = event.api.toJSON();
      localStorage.setItem("workspace-dockview-layout", JSON.stringify(layout));
    });
  };

  const createDefaultLayout = (dockApi: DockviewApi) => {
    dockApi.addPanel({
      id: "handles_tab",
      component: "handles",
      title: t("active_file_handles"),
    });

    dockApi.addPanel({
      id: "info_plist_tab",
      component: "infoPlist",
      title: "Info.plist",
    });
  };

  return (
    <DockContext.Provider value={dockContextValue}>
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
                <DockviewReact
                  // workaround: theme must not be empty, otherwise
                  //  Dockview will always insert abyss className
                  theme={themeLight}
                  className={dockViewClazz}
                  onReady={onReady}
                  components={components}
                />
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
    </DockContext.Provider>
  );
}

export function Workspace() {
  return (
    <SessionProvider>
      <WorkspaceContent />
    </SessionProvider>
  );
}

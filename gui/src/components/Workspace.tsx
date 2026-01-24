import { useEffect, useMemo, useState } from "react";
import { t } from "i18next";

import {
  type DockviewApi,
  DockviewReact,
  type DockviewReadyEvent,
  themeLight,
} from "dockview";

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import { LeftPanelView } from "./LeftPanelView";
import { BottomPanelView } from "./BottomPanelView";
import { Status, useSession } from "@/context/SessionContext";
import SessionProvider from "./SessionProvider";
import { useTheme } from "./theme-provider";
import { HandlesTab } from "./tabs/HandlesTab";
import { InfoPlistTab } from "./tabs/InfoPlistTab";
import { EntitlementsTab } from "./tabs/EntitlementsTab";
import { ModuleDetailTab } from "./tabs/ModuleDetailTab";
import { ClassDetailTab } from "./tabs/ClassDetailTab";
import { FinderTab } from "./tabs/FinderTab";
import { ImagePreviewTab } from "./tabs/ImagePreviewTab";
import { HexPreviewTab } from "./tabs/HexPreviewTab";
import { TextEditorTab } from "./tabs/TextEditorTab";
import { PlistFilePreviewTab } from "./tabs/PlistFilePreviewTab";
import { SQLiteEditorTab } from "./tabs/SQLiteEditorTab";
import { FontPreviewTab } from "./tabs/FontPreviewTab";
import { BinaryCookieTab } from "./tabs/BinaryCookieTab";
import { KeyChainTab } from "./tabs/KeyChainTab";
import { UIDumpTab } from "./tabs/UIDumpTab";
import { MemoryPreviewTab } from "./tabs/MemoryPreviewTab";

import { DockContext, useDockActions } from "@/context/DockContext";

function WorkspaceContent() {
  const { status, bundle, device } = useSession();
  const { theme } = useTheme();

  useEffect(() => {
    document.title = "Grapefruit" + (bundle ? ` - ${bundle}` : "");
  }, [bundle]);

  const getStatusColor = () => {
    switch (status) {
      case Status.Ready:
        return "bg-green-500";
      case Status.Disconnected:
        return "bg-orange-500";
      case Status.Connecting:
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
    entitlements: EntitlementsTab,
    moduleDetail: ModuleDetailTab,
    classDetail: ClassDetailTab,
    finder: FinderTab,
    imagePreview: ImagePreviewTab,
    hexPreview: HexPreviewTab,
    textEditor: TextEditorTab,
    plistPreview: PlistFilePreviewTab,
    sqliteEditor: SQLiteEditorTab,
    fontPreview: FontPreviewTab,
    binaryCookie: BinaryCookieTab,
    keychain: KeyChainTab,
    uiDump: UIDumpTab,
    memory: MemoryPreviewTab,
  };

  const getLayoutKey = (device: string | null | undefined, bundle: string | null | undefined) => {
    if (!device || !bundle) return null;
    return `workspace-dockview-layout:${device}:${bundle}`;
  };

  const onReady = (event: DockviewReadyEvent) => {
    setDockApi(event.api);

    const layoutKey = getLayoutKey(device, bundle);
    const savedLayoutWithMeta = layoutKey ? localStorage.getItem(layoutKey) : null;

    if (savedLayoutWithMeta) {
      try {
        const { layout } = JSON.parse(savedLayoutWithMeta);
        event.api.fromJSON(layout);
      } catch (e) {
        console.error("Failed to restore dockview layout:", e);
        if (layoutKey) {
          localStorage.removeItem(layoutKey);
        }
        createDefaultLayout(event.api);
      }
    } else {
      createDefaultLayout(event.api);
    }

    event.api.onDidLayoutChange(() => {
      const layout = event.api.toJSON();
      const key = getLayoutKey(device, bundle);
      if (key) {
        localStorage.setItem(key, JSON.stringify({ device, bundle, layout }));
      }
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

    dockApi.addPanel({
      id: "entitlements_tab",
      component: "entitlements",
      title: "Entitlements",
    });
  };

  return (
    <DockContext.Provider value={dockContextValue}>
      <div className="flex h-screen flex-col">
        <ResizablePanelGroup
          direction="horizontal"
          className="h-full"
          autoSaveId="workspace-left-split"
        >
          <ResizablePanel
            defaultSize={20}
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
              autoSaveId="workspace-bottom-split"
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
              <ResizablePanel defaultSize={30}>
                <BottomPanelView />
              </ResizablePanel>
            </ResizablePanelGroup>
          </ResizablePanel>
        </ResizablePanelGroup>
        <footer className={`${getStatusColor()} px-4 py-1 text-xs text-white`}>
          {status === Status.Ready && t("connected")}
          {status === Status.Connecting && t("connecting")}
          {status === Status.Disconnected && t("disconnected")}
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

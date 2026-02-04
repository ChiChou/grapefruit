import { useEffect, useMemo, useState } from "react";
import { Outlet, useNavigate } from "react-router";
import { t } from "i18next";
import { PanelBottomClose, PanelBottomOpen, RefreshCw, XCircle, Unplug } from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

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
import { Status, Platform, Mode, useSession } from "@/context/SessionContext";
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
import { WebViewTab } from "./tabs/WebViewTab";
import { JSCTab } from "./tabs/JSCTab";
import { UserDefaultsTab } from "./tabs/UserDefaultsTab";
import { QuickStartTab } from "./tabs/QuickStartTab";

import { DockContext, useDockActions } from "@/context/DockContext";

function WorkspaceContent() {
  const { status, bundle, device, platform, mode, pid } = useSession();
  const navigate = useNavigate();

  // Show full workspace (left panel + dockview) for iOS app and daemon modes
  const isFruityApp = platform === Platform.Fruity && mode === Mode.App;
  const isFruityDaemon = platform === Platform.Fruity && mode === Mode.Daemon;
  const showFullWorkspace = isFruityApp || isFruityDaemon;
  const { theme } = useTheme();

  useEffect(() => {
    const target = bundle || (pid ? `PID ${pid}` : "");
    document.title = "Grapefruit" + (target ? ` - ${target}` : "");
  }, [bundle, pid]);

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

  const handleReloadPage = () => {
    window.location.reload();
  };

  const handleKillProcess = async () => {
    if (!device || !pid) return;
    try {
      await fetch(`/api/device/${device}/kill/${pid}`, { method: "POST" });
      navigate(`/list/${device}/apps`);
    } catch (e) {
      console.error("Failed to kill process:", e);
    }
  };

  const handleDetach = () => {
    if (device) {
      navigate(`/list/${device}/apps`);
    }
  };

  const [dockViewClazz, setDockViewClazz] = useState<string>(
    "dockview-theme-light",
  );

  const [bottomPanelVisible, setBottomPanelVisible] = useState(() => {
    try {
      const saved = localStorage.getItem("workspace-bottom-panel-visible");
      return saved !== null ? JSON.parse(saved) : true;
    } catch {
      return true;
    }
  });

  useEffect(() => {
    localStorage.setItem("workspace-bottom-panel-visible", JSON.stringify(bottomPanelVisible));
  }, [bottomPanelVisible]);

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
    quickstart: QuickStartTab,
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
    webview: WebViewTab,
    jsc: JSCTab,
    userdefaults: UserDefaultsTab,
  };

  const getLayoutKey = () => {
    if (!device) return null;
    const target = bundle || pid;
    if (!target) return null;
    return `workspace-dockview-layout:${device}:${mode}:${target}`;
  };

  const onReady = (event: DockviewReadyEvent) => {
    setDockApi(event.api);

    const layoutKey = getLayoutKey();
    const savedLayoutWithMeta = layoutKey
      ? localStorage.getItem(layoutKey)
      : null;

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
      const key = getLayoutKey();
      if (key) {
        localStorage.setItem(key, JSON.stringify({ device, mode, target: bundle || pid, layout }));
      }
    });
  };

  const createDefaultLayout = (dockApi: DockviewApi) => {
    if (isFruityApp) {
      // iOS App mode - Quick Start tab
      dockApi.addPanel({
        id: "quickstart_tab",
        component: "quickstart",
        title: t("quickstart"),
      });
    } else if (isFruityDaemon) {
      // iOS Daemon mode - Finder tab
      dockApi.addPanel({
        id: "finder_tab",
        component: "finder",
        title: "Finder",
        params: { path: "/" },
      });
    }
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
            {showFullWorkspace ? (
              bottomPanelVisible ? (
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
              ) : (
                <DockviewReact
                  theme={themeLight}
                  className={dockViewClazz}
                  onReady={onReady}
                  components={components}
                />
              )
            ) : (
              <div className="h-full overflow-auto">
                <Outlet />
              </div>
            )}
          </ResizablePanel>
        </ResizablePanelGroup>
        <footer className={`${getStatusColor()} px-4 py-1 text-xs text-white flex items-center justify-between`}>
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              <button
                type="button"
                className="hover:bg-white/20 px-1 py-0.5 rounded transition-colors cursor-pointer"
              >
                {status === Status.Ready && t("connected")}
                {status === Status.Connecting && t("connecting")}
                {status === Status.Disconnected && t("disconnected")}
              </button>
            </DropdownMenuTrigger>
            <DropdownMenuContent align="start">
              <DropdownMenuItem onClick={handleReloadPage}>
                <RefreshCw className="w-4 h-4 mr-2" />
                {t("reload_page")}
              </DropdownMenuItem>
              <DropdownMenuItem
                onClick={handleKillProcess}
                disabled={status !== Status.Ready}
              >
                <XCircle className="w-4 h-4 mr-2" />
                {t("kill_process")}
              </DropdownMenuItem>
              <DropdownMenuItem onClick={handleDetach}>
                <Unplug className="w-4 h-4 mr-2" />
                {t("detach")}
              </DropdownMenuItem>
            </DropdownMenuContent>
          </DropdownMenu>
          {showFullWorkspace && (
            <button
              type="button"
              onClick={() => setBottomPanelVisible(!bottomPanelVisible)}
              className="p-0.5 hover:bg-white/20 rounded transition-colors"
              title={bottomPanelVisible ? t("hide_panel") : t("show_panel")}
            >
              {bottomPanelVisible ? (
                <PanelBottomClose className="w-4 h-4" />
              ) : (
                <PanelBottomOpen className="w-4 h-4" />
              )}
            </button>
          )}
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

import { useEffect, useMemo, useState } from "react";
import { t } from "i18next";
import { StatusBar } from "./StatusBar";

import {
  type DockviewApi,
  type DockviewTheme,
  DockviewReact,
  type DockviewReadyEvent,
} from "dockview";

import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import { LeftPanelView } from "./LeftPanelView";
import { BottomPanelView } from "./BottomPanelView";
import { useSession } from "@/context/SessionContext";
import SessionProvider from "../providers/SessionProvider";
import { FruityHandlesTab } from "../tabs/FruityHandlesTab";
import { FruityInfoPlistTab } from "../tabs/FruityInfoPlistTab";
import { FruityEntitlementsTab } from "../tabs/FruityEntitlementsTab";
import { ModuleDetailTab } from "../tabs/ModuleDetailTab";
import { FruityClassDetailTab } from "../tabs/FruityClassDetailTab";
import { DroidClassDetailTab } from "../tabs/DroidClassDetailTab";
import { FinderTab } from "../tabs/FinderTab";
import { ImagePreviewTab } from "../tabs/ImagePreviewTab";
import { HexPreviewTab } from "../tabs/HexPreviewTab";
import { TextEditorTab } from "../tabs/TextEditorTab";
import { FruityPlistPreviewTab } from "../tabs/FruityPlistPreviewTab";
import { SQLiteEditorTab } from "../tabs/SQLiteEditorTab";
import { FontPreviewTab } from "../tabs/FontPreviewTab";
import { FruityBinaryCookieTab } from "../tabs/FruityBinaryCookieTab";
import { FruityKeychainTab } from "../tabs/FruityKeychainTab";
import { FruityUIDumpTab } from "../tabs/FruityUIDumpTab";
import { MemoryPreviewTab } from "../tabs/MemoryPreviewTab";
import { FruityWebViewTab } from "../tabs/FruityWebViewTab";
import { FruityJSCTab } from "../tabs/FruityJSCTab";
import { FruityUserDefaultsTab } from "../tabs/FruityUserDefaultsTab";
import { QuickStartTab } from "../tabs/QuickStartTab";
import { FruityDisassemblyTab } from "../tabs/FruityDisassemblyTab";
import { FruityURLLoadingTab } from "../tabs/FruityURLLoadingTab";
import { FlutterMethodChannelsTab } from "../tabs/FlutterMethodChannelsTab";
import { DroidHandlesTab } from "../tabs/DroidHandlesTab";
import { DroidKeystoreTab } from "../tabs/DroidKeystoreTab";
import { DroidManifestTab } from "../tabs/DroidManifestTab";
import { NoCloseTabHeader } from "../tabs/NoCloseTabHeader";

import { DockContext, useDockActions } from "@/context/DockContext";
import { R2Provider } from "../providers/R2Provider";

const themeApp: DockviewTheme = {
  name: "app",
  className: "dockview-theme-app",
};

function WorkspaceContent() {
  const { bundle, device, mode, pid } = useSession();

  useEffect(() => {
    const target = bundle || (pid ? `PID ${pid}` : "");
    document.title = "Grapefruit" + (target ? ` - ${target}` : "");
  }, [bundle, pid]);

  const [bottomPanelVisible, setBottomPanelVisible] = useState(() => {
    try {
      const saved = localStorage.getItem("workspace-bottom-panel-visible");
      return saved !== null ? JSON.parse(saved) : true;
    } catch {
      return true;
    }
  });

  useEffect(() => {
    localStorage.setItem(
      "workspace-bottom-panel-visible",
      JSON.stringify(bottomPanelVisible),
    );
  }, [bottomPanelVisible]);

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
    handles: FruityHandlesTab,
    infoPlist: FruityInfoPlistTab,
    entitlements: FruityEntitlementsTab,
    moduleDetail: ModuleDetailTab,
    classDetail: FruityClassDetailTab,
    javaClassDetail: DroidClassDetailTab,
    finder: FinderTab,
    imagePreview: ImagePreviewTab,
    hexPreview: HexPreviewTab,
    textEditor: TextEditorTab,
    plistPreview: FruityPlistPreviewTab,
    sqliteEditor: SQLiteEditorTab,
    fontPreview: FontPreviewTab,
    binaryCookie: FruityBinaryCookieTab,
    keychain: FruityKeychainTab,
    uiDump: FruityUIDumpTab,
    memory: MemoryPreviewTab,
    webview: FruityWebViewTab,
    jsc: FruityJSCTab,
    userdefaults: FruityUserDefaultsTab,
    disassembly: FruityDisassemblyTab,
    httpLog: FruityURLLoadingTab,
    flutterChannels: FlutterMethodChannelsTab,
    droidHandles: DroidHandlesTab,
    keystore: DroidKeystoreTab,
    droidManifest: DroidManifestTab,
  };

  const tabComponents = {
    noClose: NoCloseTabHeader,
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
        localStorage.setItem(
          key,
          JSON.stringify({ device, mode, target: bundle || pid, layout }),
        );
      }
    });
  };

  const createDefaultLayout = (dockApi: DockviewApi) => {
    dockApi.addPanel({
      id: "quickstart_tab",
      component: "quickstart",
      tabComponent: "noClose",
      title: t("quickstart"),
    });
  };

  return (
    <DockContext.Provider value={dockContextValue}>
      <div className="flex h-screen flex-col">
        <ResizablePanelGroup
          orientation="horizontal"
          className="h-full"
          autoSaveId="workspace-left-split"
        >
          <ResizablePanel
            defaultSize="20%"
            minSize="15%"
            className="flex flex-col"
          >
            <LeftPanelView />
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel>
            {bottomPanelVisible ? (
              <ResizablePanelGroup
                orientation="vertical"
                className="h-full"
                autoSaveId="workspace-bottom-split"
              >
                <ResizablePanel>
                  <DockviewReact
                    theme={themeApp}
                    onReady={onReady}
                    components={components}
                    tabComponents={tabComponents}
                  />
                </ResizablePanel>
                <ResizableHandle />
                <ResizablePanel defaultSize="30%">
                  <BottomPanelView />
                </ResizablePanel>
              </ResizablePanelGroup>
            ) : (
              <DockviewReact
                theme={themeApp}
                onReady={onReady}
                components={components}
                tabComponents={tabComponents}
              />
            )}
          </ResizablePanel>
        </ResizablePanelGroup>
        <StatusBar
          bottomPanelVisible={bottomPanelVisible}
          setBottomPanelVisible={setBottomPanelVisible}
        />
      </div>
    </DockContext.Provider>
  );
}

export function Workspace() {
  return (
    <SessionProvider>
      <R2Provider>
        <WorkspaceContent />
      </R2Provider>
    </SessionProvider>
  );
}

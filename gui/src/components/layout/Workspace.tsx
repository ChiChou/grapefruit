import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { t } from "i18next";
import { StatusBar } from "./StatusBar";

import {
  type DockviewApi,
  type DockviewTheme,
  DockviewReact,
  type DockviewReadyEvent,
} from "dockview";

import type { PanelImperativeHandle } from "react-resizable-panels";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import { LeftPanelView } from "./LeftPanelView";
import { BottomPanelView } from "./BottomPanelView";
import { CommandPalette } from "./CommandPalette";
import { useSession } from "@/context/SessionContext";
import SessionProvider from "../providers/SessionProvider";
import { FruityHandlesTab } from "../tabs/FruityHandlesTab";
import { FruityInfoPlistTab } from "../tabs/FruityInfoPlistTab";
import { FruityEntitlementsTab } from "../tabs/FruityEntitlementsTab";
import {
  ModuleImportsTab,
  ModuleSectionsTab,
  ModuleClassesTab,
  ModuleSymbolsTab,
  ModuleExportedTab,
} from "../tabs/ModuleViewTabs";
import { FruityClassDetailTab } from "../tabs/FruityClassDetailTab";
import { FruityClassDumpTab } from "../tabs/FruityClassDumpTab";
import { DroidClassDetailTab } from "../tabs/DroidClassDetailTab";
import { ApkBrowserTab } from "../tabs/ApkBrowserTab";
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
import { MemoryScanTab } from "../tabs/MemoryScanTab";
import { FruityWebViewTab } from "../tabs/FruityWebViewTab";
import { FruityJSCTab } from "../tabs/FruityJSCTab";
import { FruityUserDefaultsTab } from "../tabs/FruityUserDefaultsTab";
import { HomeTab } from "../tabs/HomeTab";
import { FruityDisassemblyTab } from "../tabs/FruityDisassemblyTab";
import { FruityNSURLTab } from "../tabs/FruityNSURLTab";
import { FlutterMethodChannelsTab } from "../tabs/FlutterMethodChannelsTab";
import { JNITab } from "../tabs/DroidJNITab";
import { DroidHandlesTab } from "../tabs/DroidHandlesTab";
import { DroidKeystoreTab } from "../tabs/DroidKeystoreTab";
import { FruityInfoPlistInsightsTab } from "../tabs/FruityInfoPlistInsightsTab";
import { DroidManifestTab } from "../tabs/DroidManifestTab";
import { DroidProvidersTab } from "../tabs/DroidProvidersTab";
import { FruityXPCTab } from "../tabs/FruityXPCTab";
import { ReactNativeTab } from "../tabs/ReactNativeTab";
import { PrivacyTab } from "../tabs/PrivacyTab";
import { XCPrivacyTab } from "../tabs/XCPrivacyTab";
import { DroidHttpTab } from "../tabs/DroidHttpTab";
import { AssetCatalogTab } from "../tabs/AssetCatalogTab";
import { ChecksecTab } from "../tabs/ChecksecTab";
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
    const panel = bottomPanelRef.current;
    if (!panel) return;
    if (bottomPanelVisible) {
      panel.expand();
    } else {
      panel.collapse();
    }
    mountedRef.current = true;
  }, [bottomPanelVisible]);

  const bottomPanelRef = useRef<PanelImperativeHandle>(null);
  const mountedRef = useRef(false);

  const [dockApi, setDockApi] = useState<DockviewApi | null>(null);
  const { openSingletonPanel, openFilePanel } = useDockActions(dockApi);

  const getLayoutKey = useCallback(() => {
    if (!device) return null;
    const target = bundle || pid;
    if (!target) return null;
    return `workspace-dockview-layout:${device}:${mode}:${target}`;
  }, [device, bundle, pid, mode]);

  const resetLayout = useCallback(() => {
    if (!dockApi) return;
    const key = getLayoutKey();
    if (key) localStorage.removeItem(key);
    // Remove all existing panels
    for (const panel of dockApi.panels) {
      panel.api.close();
    }
    createDefaultLayout(dockApi);
  }, [dockApi, getLayoutKey]);

  const [commandPaletteOpen, setCommandPaletteOpen] = useState(false);

  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setCommandPaletteOpen((prev) => !prev);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  const dockContextValue = useMemo(
    () => ({
      api: dockApi,
      openSingletonPanel,
      openFilePanel,
      resetLayout,
    }),
    [dockApi, openSingletonPanel, openFilePanel, resetLayout],
  );

  const components = {
    home: HomeTab,
    apkBrowser: ApkBrowserTab,
    handles: FruityHandlesTab,
    infoPlist: FruityInfoPlistTab,
    entitlements: FruityEntitlementsTab,
    moduleDetail: ModuleImportsTab,
    moduleImports: ModuleImportsTab,
    moduleSections: ModuleSectionsTab,
    moduleClasses: ModuleClassesTab,
    moduleSymbols: ModuleSymbolsTab,
    moduleExported: ModuleExportedTab,
    classDetail: FruityClassDetailTab,
    classDump: FruityClassDumpTab,
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
    memoryScan: MemoryScanTab,
    webview: FruityWebViewTab,
    jsc: FruityJSCTab,
    userdefaults: FruityUserDefaultsTab,
    disassembly: FruityDisassemblyTab,
    nsurl: FruityNSURLTab,
    flutterChannels: FlutterMethodChannelsTab,
    jni: JNITab,
    droidHandles: DroidHandlesTab,
    keystore: DroidKeystoreTab,
    infoPlistInsights: FruityInfoPlistInsightsTab,
    droidManifest: DroidManifestTab,
    droidProviders: DroidProvidersTab,
    xpc: FruityXPCTab,
    reactNative: ReactNativeTab,
    privacy: PrivacyTab,
    xcprivacy: XCPrivacyTab,
    droidHttp: DroidHttpTab,
    assetCatalog: AssetCatalogTab,
    checksec: ChecksecTab,
  };

  const tabComponents = {
    noClose: NoCloseTabHeader,
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
      id: "home_tab",
      component: "home",
      tabComponent: "noClose",
      title: t("home"),
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
            <ResizablePanelGroup
              orientation="vertical"
              className="h-full"
              autoSaveId="workspace-bottom-split"
            >
              <ResizablePanel id="dock">
                <DockviewReact
                  theme={themeApp}
                  onReady={onReady}
                  components={components}
                  tabComponents={tabComponents}
                />
              </ResizablePanel>
              <ResizableHandle />
              <ResizablePanel
                id="bottom"
                panelRef={bottomPanelRef}
                defaultSize="30%"
                minSize="10%"
                collapsible
                collapsedSize={0}
                onResize={(size) => {
                  if (!mountedRef.current) return;
                  setBottomPanelVisible(size.asPercentage > 0);
                }}
              >
                <BottomPanelView />
              </ResizablePanel>
            </ResizablePanelGroup>
          </ResizablePanel>
        </ResizablePanelGroup>
        <StatusBar
          bottomPanelVisible={bottomPanelVisible}
          setBottomPanelVisible={setBottomPanelVisible}
          onOpenCommandPalette={() => setCommandPaletteOpen(true)}
          onResetLayout={resetLayout}
        />
      </div>
      <CommandPalette open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen} />
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

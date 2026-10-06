import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { t } from "i18next";
import { StatusBar } from "./StatusBar";
import { WorkspaceActions, WorkspaceActionsContext } from "./WorkspaceActions";

import {
  type DockviewApi,
  type DockviewTheme,
  type AddPanelOptions,
  DockviewReact,
  type DockviewReadyEvent,
} from "dockview";

import type { PanelImperativeHandle } from "react-resizable-panels";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";

import { ActivityBar, LeftPanelView } from "./LeftPanelView";
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
import { FilesTab } from "../tabs/FilesTab";
import { ImagePreviewTab } from "../tabs/ImagePreviewTab";
import { AudioPreviewTab } from "../tabs/AudioPreviewTab";
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
import { DisassemblyTab } from "../tabs/DisassemblyTab";
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
import { HermesFileTab } from "../tabs/HermesFileTab";
import { PrivacyTab } from "../tabs/PrivacyTab";
import { XCPrivacyTab } from "../tabs/XCPrivacyTab";
import { DroidHttpTab } from "../tabs/DroidHttpTab";
import { DroidResourcesTab } from "../tabs/DroidResourcesTab";
import { DroidWebViewTab } from "../tabs/DroidWebViewTab";
import { AssetCatalogTab } from "../tabs/AssetCatalogTab";
import { ChecksecTab } from "../tabs/ChecksecTab";
import { CryptoTab } from "../tabs/CryptoTab";
import { Il2CppClassDetailTab } from "../tabs/Il2CppClassDetailTab";
import { Il2CppClassDumpTab } from "../tabs/Il2CppClassDumpTab";
import { DexViewerTab } from "../tabs/DexViewerTab";
import { BinaryOverviewTab } from "../tabs/BinaryOverviewTab";
import { MemoryMapsTab } from "../tabs/MemoryMapsTab";
import { BinariesTab } from "../tabs/BinariesTab";
import { R2SearchTab } from "../tabs/R2SearchTab";
import { TypeEditorTab } from "../tabs/TypeEditorTab";
import { XrefGraphTab } from "../tabs/XrefGraphTab";
import { BookmarksTab } from "../tabs/BookmarksTab";
import { R2GraphTab } from "../tabs/R2GraphTab";
import { R2HexTab } from "../tabs/R2HexTab";
import { R2DisasmTab } from "../tabs/R2DisasmTab";
import { NoCloseTabHeader } from "../tabs/NoCloseTabHeader";

import { DockContext } from "@/context/DockContext";
import { R2Provider } from "@/context/R2Context";

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

  const [bottomPanelVisible, setBottomPanelVisible] = useState<boolean>(() => {
    try {
      const saved = localStorage.getItem("workspace-bottom-panel-visible");
      return saved !== null ? JSON.parse(saved) === true : true;
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

  const [sidebarVisible, setSidebarVisible] = useState(() => {
    try {
      return localStorage.getItem("workspace-sidebar-visible") !== "false";
    } catch {
      return true;
    }
  });
  const sidebarRef = useRef<PanelImperativeHandle>(null);
  const sidebarMounted = useRef(false);
  const sidebarSize = useRef<number | null>(null);
  if (sidebarSize.current === null) {
    try {
      const saved = Number(localStorage.getItem("workspace-sidebar-size"));
      sidebarSize.current = saved > 0 && saved <= 40 ? saved : 18;
    } catch {
      sidebarSize.current = 18;
    }
  }

  useEffect(() => {
    localStorage.setItem("workspace-sidebar-visible", JSON.stringify(sidebarVisible));
    const panel = sidebarRef.current;
    if (!panel) return;
    if (sidebarVisible) {
      const size = sidebarSize.current ?? 18;
      panel.expand();
      panel.resize(`${size}%`);
    } else panel.collapse();
    sidebarMounted.current = true;
  }, [sidebarVisible]);

  const [dockApi, setDockApi] = useState<DockviewApi | null>(null);

  const openSingletonPanel = useCallback(
    (options: AddPanelOptions) => {
      if (!dockApi) return;
      const existing = dockApi.getPanel(options.id);
      if (existing) {
        if (options.params) existing.api.updateParameters(options.params);
        existing.api.setActive();
        return;
      }
      dockApi.addPanel(options);
    },
    [dockApi],
  );

  const openFilePanel = useCallback(
    (options: AddPanelOptions) => {
      if (!dockApi) return;
      const existing = dockApi.getPanel(options.id);
      if (existing) {
        existing.api.setActive();
        return;
      }
      dockApi.addPanel(options);
    },
    [dockApi],
  );

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
      if (e.defaultPrevented || e.isComposing || e.repeat || e.altKey || e.shiftKey || !(e.metaKey || e.ctrlKey)) return;
      const key = e.key.toLowerCase();
      if (!["k", "b", "j"].includes(key)) return;
      e.preventDefault();
      if (key === "k") setCommandPaletteOpen((prev) => !prev);
      if (key === "b") setSidebarVisible((prev) => !prev);
      if (key === "j") setBottomPanelVisible((prev) => !prev);
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
    files: FilesTab,
    imagePreview: ImagePreviewTab,
    audioPreview: AudioPreviewTab,
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
    disassembly: DisassemblyTab,
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
    hermesFile: HermesFileTab,
    privacy: PrivacyTab,
    xcprivacy: XCPrivacyTab,
    droidHttp: DroidHttpTab,
    droidResources: DroidResourcesTab,
    droidWebview: DroidWebViewTab,
    assetCatalog: AssetCatalogTab,
    checksec: ChecksecTab,
    crypto: CryptoTab,
    il2cppClassDetail: Il2CppClassDetailTab,
    il2cppClassDump: Il2CppClassDumpTab,
    dexViewer: DexViewerTab,
    binaryOverview: BinaryOverviewTab,
    memoryMaps: MemoryMapsTab,
    binaries: BinariesTab,
    r2Search: R2SearchTab,
    typeEditor: TypeEditorTab,
    xrefGraph: XrefGraphTab,
    bookmarks: BookmarksTab,
    r2Graph: R2GraphTab,
    r2Hex: R2HexTab,
    r2Disasm: R2DisasmTab,
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

  const r2StorageKey = `${device}:${mode}:${bundle || pid}`;

  return (
    <R2Provider storageKey={r2StorageKey}>
    <DockContext.Provider value={dockContextValue}>
      <WorkspaceActionsContext.Provider value={{
        sidebarVisible,
        bottomPanelVisible,
        onToggleSidebar: () => setSidebarVisible((prev) => !prev),
        onTogglePanel: () => setBottomPanelVisible((prev) => !prev),
        onOpenCommandPalette: () => setCommandPaletteOpen(true),
        onResetLayout: resetLayout,
      }}>
      <div className="flex h-screen flex-col overflow-hidden bg-background text-foreground">
        <div className="flex min-h-0 flex-1">
          <ActivityBar onNavigate={() => setSidebarVisible(true)} />
          <ResizablePanelGroup
            orientation="horizontal"
            className="min-w-0 flex-1"
          >
            <ResizablePanel
              id="left"
              panelRef={sidebarRef}
              defaultSize={`${sidebarVisible ? sidebarSize.current : 0}%`}
              minSize="180px"
              maxSize="40%"
              collapsible
              collapsedSize={0}
              onResize={(size) => {
                if (!sidebarMounted.current) return;
                if (size.asPercentage > 0) {
                  sidebarSize.current = size.asPercentage;
                  localStorage.setItem("workspace-sidebar-size", String(size.asPercentage));
                }
                setSidebarVisible(size.asPercentage > 0);
              }}
              className="flex flex-col"
            >
              <LeftPanelView />
            </ResizablePanel>
            <ResizableHandle />
            <ResizablePanel id="main">
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
                    rightHeaderActionsComponent={WorkspaceActions}
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
        </div>
        <StatusBar />
      </div>
      <CommandPalette open={commandPaletteOpen} onOpenChange={setCommandPaletteOpen} />
      </WorkspaceActionsContext.Provider>
    </DockContext.Provider>
    </R2Provider>
  );
}

export function Workspace() {
  return (
    <SessionProvider>
      <WorkspaceContent />
    </SessionProvider>
  );
}

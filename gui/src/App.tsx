import { Routes, Route } from "react-router";
import { useTranslation } from "react-i18next";

import "dockview/dist/styles/dockview.css";

import "./App.css";
import { WelcomePage } from "./components/pages/WelcomePage";
import { DefaultMessage } from "./components/pages/DefaultMessage";
import { AppsView } from "./components/pages/AppsView";
import { ProcessesView } from "./components/pages/ProcessesView";
import { Workspace } from "./components/layout/Workspace";
import { WorkspaceIndex } from "./components/layout/WorkspaceIndex";
import { HermesPage } from "./components/pages/HermesPage";
import { R2Page } from "./components/pages/R2Page";

import { FruityGeneralPanel } from "./components/panels/FruityGeneralPanel";
import { FruityDevicePanel } from "./components/panels/FruityDevicePanel";
import { DroidGeneralPanel } from "./components/panels/DroidGeneralPanel";
import { DroidComponentsPanel } from "./components/panels/DroidComponentsPanel";
import { DroidDevicePanel } from "./components/panels/DroidDevicePanel";
import { ModulesPanel } from "./components/panels/ModulesPanel";
import { FruityClassesPanel } from "./components/panels/FruityClassesPanel";
import { DroidClassesPanel } from "./components/panels/DroidClassesPanel";
import { FruityURLSchemesPanel } from "./components/panels/FruityURLSchemesPanel";
import { DroidURLSchemesPanel } from "./components/panels/DroidURLSchemesPanel";
import { FruityGeolocationPanel } from "./components/panels/FruityGeolocationPanel";
import { FruityHooksPanel } from "./components/panels/FruityHooksPanel";
import { FruityPluginsPanel } from "./components/panels/FruityPluginsPanel";
import { DroidHooksPanel } from "./components/panels/DroidHooksPanel";
import { PlaceholderPanel } from "./components/panels/PlaceholderPanel";
import { ThreadsPanel } from "./components/panels/ThreadsPanel";
import { Il2CppPanel } from "./components/panels/Il2CppPanel";

import { Platform, useSession } from "./context/SessionContext";
import { ErrorBoundary } from "./components/shared/ErrorBoundary";
import { AlertTriangle } from "lucide-react";

function GeneralPanelRoute() {
  const { platform } = useSession();
  return platform === Platform.Droid ? <DroidGeneralPanel /> : <FruityGeneralPanel />;
}

function ClassesPanelRoute() {
  const { platform } = useSession();
  return platform === Platform.Droid ? <DroidClassesPanel /> : <FruityClassesPanel />;
}

function URLSchemesPanelRoute() {
  const { platform } = useSession();
  return platform === Platform.Droid ? <DroidURLSchemesPanel /> : <FruityURLSchemesPanel />;
}

function DevicePanelRoute() {
  const { platform } = useSession();
  return platform === Platform.Droid ? <DroidDevicePanel /> : <FruityDevicePanel />;
}

function HooksPanelRoute() {
  const { platform } = useSession();
  return platform === Platform.Droid ? <DroidHooksPanel /> : <FruityHooksPanel />;
}

function App() {
  const { t } = useTranslation();

  return (
    <>
      <div className="fixed top-0 left-0 right-0 z-50 block bg-yellow-100 px-4 py-3 text-center text-sm font-medium text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 sm:hidden">
        <div className="flex items-center justify-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          <span>{t("desktop_only_warning")}</span>
        </div>
      </div>
      <Routes>
        {/* Welcome page with device list */}
        <Route path="/" element={<WelcomePage />}>
          <Route index element={<DefaultMessage />} />
          {/* Apps list for a device */}
          <Route path="list/:udid/apps" element={<AppsView />} />
          {/* Processes list for a device */}
          <Route path="list/:udid/processes" element={<ProcessesView />} />
        </Route>

        {/* Standalone decompiler tools */}
        <Route path="/decompiler/hermes" element={<ErrorBoundary><HermesPage /></ErrorBoundary>} />
        <Route path="/decompiler/radare2" element={<ErrorBoundary><R2Page /></ErrorBoundary>} />

        {/* Workspace with platform and mode as route params */}
        <Route path="/workspace/:platform/:device/:mode/:target" element={<ErrorBoundary><Workspace /></ErrorBoundary>}>
          {/* Default view based on platform/mode */}
          <Route index element={<WorkspaceIndex />} />
          {/* Platform-aware panels */}
          <Route path="general" element={<GeneralPanelRoute />} />
          <Route path="modules" element={<ModulesPanel />} />
          <Route path="classes" element={<ClassesPanelRoute />} />
          <Route path="urls" element={<URLSchemesPanelRoute />} />
          <Route path="extensions" element={<FruityPluginsPanel />} />
          <Route path="geolocation" element={<FruityGeolocationPanel />} />
          <Route path="hooks" element={<HooksPanelRoute />} />
          {/* Android (droid) panels */}
          <Route path="components" element={<DroidComponentsPanel />} />
          <Route path="device" element={<DevicePanelRoute />} />
          <Route path="il2cpp" element={<Il2CppPanel />} />
          <Route path="threads" element={<ThreadsPanel />} />
          {/* Placeholder for unsupported modes */}
          <Route path="placeholder" element={<PlaceholderPanel />} />
        </Route>
      </Routes>
    </>
  );
}

export default App;

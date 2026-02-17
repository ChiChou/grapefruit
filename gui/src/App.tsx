import { Routes, Route } from "react-router";
import { useTranslation } from "react-i18next";

import "dockview/dist/styles/dockview.css";

import "./App.css";
import { WelcomePage } from "./components/WelcomePage";
import { DefaultMessage } from "./components/DefaultMessage";
import { AppsView } from "./components/AppsView";
import { ProcessesView } from "./components/ProcessesView";
import { Workspace } from "./components/Workspace";
import { WorkspaceIndex } from "./components/WorkspaceIndex";

import { GeneralPanel } from "./components/panels/GeneralPanel";
import { DroidGeneralPanel } from "./components/panels/DroidGeneralPanel";
import { DroidComponentsPanel } from "./components/panels/DroidComponentsPanel";
import { DroidDevicePanel } from "./components/panels/DroidDevicePanel";
import { ModulesPanel } from "./components/panels/ModulesPanel";
import { ClassesPanel } from "./components/panels/ClassesPanel";
import { DroidClassesPanel } from "./components/panels/DroidClassesPanel";
import { URLSchemesPanel } from "./components/panels/URLSchemesPanel";
import { GeolocationPanel } from "./components/panels/GeolocationPanel";
import { HooksPanel } from "./components/panels/HooksPanel";
import { PlaceholderPanel } from "./components/panels/PlaceholderPanel";

import { Platform, useSession } from "./context/SessionContext";
import { AlertTriangle } from "lucide-react";

function GeneralPanelRoute() {
  const { platform } = useSession();
  return platform === Platform.Droid ? <DroidGeneralPanel /> : <GeneralPanel />;
}

function ClassesPanelRoute() {
  const { platform } = useSession();
  return platform === Platform.Droid ? <DroidClassesPanel /> : <ClassesPanel />;
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

        {/* Workspace with platform and mode as route params */}
        <Route path="/workspace/:platform/:device/:mode/:target" element={<Workspace />}>
          {/* Default view based on platform/mode */}
          <Route index element={<WorkspaceIndex />} />
          {/* Platform-aware panels */}
          <Route path="general" element={<GeneralPanelRoute />} />
          <Route path="modules" element={<ModulesPanel />} />
          <Route path="classes" element={<ClassesPanelRoute />} />
          <Route path="urls" element={<URLSchemesPanel />} />
          <Route path="geolocation" element={<GeolocationPanel />} />
          <Route path="hooks" element={<HooksPanel />} />
          {/* Android (droid) panels */}
          <Route path="components" element={<DroidComponentsPanel />} />
          <Route path="device" element={<DroidDevicePanel />} />
          {/* Placeholder for unsupported modes */}
          <Route path="placeholder" element={<PlaceholderPanel />} />
        </Route>
      </Routes>
    </>
  );
}

export default App;

import { Routes, Route, Navigate } from "react-router";
import { useTranslation } from "react-i18next";
import "./App.css";
import { WelcomePage } from "./components/WelcomePage";
import { DefaultMessage } from "./components/DefaultMessage";
import { AppsView } from "./components/AppsView";
import { Workspace } from "./components/Workspace";

import { GeneralPanel } from "./components/panels/GeneralPanel";
import { ModulesPanel } from "./components/panels/ModulesPanel";
import { ClassesPanel } from "./components/panels/ClassesPanel";
import { FilesPanel } from "./components/panels/FilesPanel";

import { AlertTriangle } from "lucide-react";

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
        <Route path="/" element={<WelcomePage />}>
          <Route index element={<DefaultMessage />} />
          <Route path="apps/:udid" element={<AppsView />} />
        </Route>
        <Route path="/workspace/:device/:bundle" element={<Workspace />}>
          <Route index element={<Navigate to="general" replace />} />
          <Route path="general" element={<GeneralPanel />} />
          <Route path="modules" element={<ModulesPanel />} />
          <Route path="classes" element={<ClassesPanel />} />
          <Route path="files" element={<FilesPanel />} />
        </Route>
      </Routes>
    </>
  );
}

export default App;

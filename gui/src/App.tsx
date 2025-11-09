import { Routes, Route, Navigate } from "react-router";
import { useTranslation } from "react-i18next";
import "./App.css";
import { WelcomePage } from "./components/WelcomePage";
import { DefaultMessage } from "./components/DefaultMessage";
import { AppsView } from "./components/AppsView";
import { Workspace } from "./components/Workspace";
import { GeneralView } from "./components/GeneralView";
import { ModulesView } from "./components/ModulesView";
import { ClassesView } from "./components/ClassesView";
import { FilesView } from "./components/FilesView";
import { AlertTriangle } from "lucide-react";

function App() {
  const { t } = useTranslation();

  return (
    <>
      <div className="block bg-yellow-100 px-4 py-3 text-center text-sm font-medium text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 sm:hidden">
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
          <Route path="general" element={<GeneralView />} />
          <Route path="modules" element={<ModulesView />} />
          <Route path="classes" element={<ClassesView />} />
          <Route path="files" element={<FilesView />} />
        </Route>
      </Routes>
    </>
  );
}

export default App;

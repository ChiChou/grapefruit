import { Routes, Route } from "react-router";
import "./App.css";
import { WelcomePage } from "./components/WelcomePage";
import { DefaultMessage } from "./components/DefaultMessage";
import { AppsView } from "./components/AppsView";
import { Workspace } from "./components/Workspace";
import { AlertTriangle } from "lucide-react";

function App() {
  return (
    <>
      <div className="block bg-yellow-100 px-4 py-3 text-center text-sm font-medium text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200 sm:hidden">
        <div className="flex items-center justify-center gap-2">
          <AlertTriangle className="h-4 w-4" />
          <span>Grapefruit is designed for desktop browsers only</span>
        </div>
      </div>
      <Routes>
        <Route path="/" element={<WelcomePage />}>
          <Route index element={<DefaultMessage />} />
          <Route path="apps/:udid" element={<AppsView />} />
        </Route>
        <Route path="/workspace/:udid/:identifier" element={<Workspace />} />
      </Routes>
    </>
  );
}

export default App;

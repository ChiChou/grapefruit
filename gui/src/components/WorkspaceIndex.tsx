import { Navigate } from "react-router";
import { Mode, useSession } from "@/context/SessionContext";

/**
 * Redirects to the default tab for the workspace based on platform and mode.
 * This ensures the URL reflects the active sidebar tab.
 */
export function WorkspaceIndex() {
  const { mode } = useSession();

  if (mode === Mode.App) {
    return <Navigate to="general" replace />;
  }

  if (mode === Mode.Daemon) {
    return <Navigate to="modules" replace />;
  }

  return <Navigate to="general" replace />;
}

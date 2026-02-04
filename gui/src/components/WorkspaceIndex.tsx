import { Platform, Mode, useSession } from "@/context/SessionContext";
import { GeneralPanel } from "./panels/GeneralPanel";
import { ModulesPanel } from "./panels/ModulesPanel";
import { PlaceholderPanel } from "./panels/PlaceholderPanel";

/**
 * Renders the default panel for the workspace based on platform and mode.
 * Instead of redirecting, this directly renders the appropriate component.
 */
export function WorkspaceIndex() {
  const { platform, mode } = useSession();

  // iOS App mode - show GeneralPanel
  if (platform === Platform.Fruity && mode === Mode.App) {
    return <GeneralPanel />;
  }

  // iOS Daemon mode - show ModulesPanel
  if (platform === Platform.Fruity && mode === Mode.Daemon) {
    return <ModulesPanel />;
  }

  // Android App mode - placeholder for now
  if (platform === Platform.Droid && mode === Mode.App) {
    return <PlaceholderPanel />;
  }

  // Android Daemon mode - placeholder for now
  if (platform === Platform.Droid && mode === Mode.Daemon) {
    return <PlaceholderPanel />;
  }

  // Fallback
  return <PlaceholderPanel />;
}

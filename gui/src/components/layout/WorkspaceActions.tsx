import { createContext, useContext } from "react";
import { useTranslation } from "react-i18next";
import { PanelBottom, PanelLeft, RotateCcw, Search } from "lucide-react";
import { Button } from "@/components/ui/button";

interface WorkspaceActionsValue {
  sidebarVisible: boolean;
  bottomPanelVisible: boolean;
  onToggleSidebar: () => void;
  onTogglePanel: () => void;
  onOpenCommandPalette: () => void;
  onResetLayout: () => void;
}

export const WorkspaceActionsContext = createContext<WorkspaceActionsValue | null>(null);

export function WorkspaceActions() {
  const { t } = useTranslation();
  const actions = useContext(WorkspaceActionsContext);
  if (!actions) return null;
  const {
    sidebarVisible,
    bottomPanelVisible,
    onToggleSidebar,
    onTogglePanel,
    onOpenCommandPalette,
    onResetLayout,
  } = actions;
  const mac = /Mac|iPhone|iPad|iPod/.test(navigator.platform);

  return (
    <div className="native-chrome flex h-full items-center gap-0.5 px-1">
      <Button
        variant="ghost"
        size="icon-xs"
        aria-label={t("command_palette")}
        aria-keyshortcuts={mac ? "Meta+k" : "Control+k"}
        title={`${t("command_palette")} (${mac ? "⌘" : "Ctrl+"}K)`}
        onClick={onOpenCommandPalette}
      >
        <Search className="text-muted-foreground" />
      </Button>
      <Button
        variant="ghost"
        size="icon-xs"
        aria-label={t("toggle_sidebar")}
        title={t("toggle_sidebar")}
        aria-pressed={sidebarVisible}
        aria-keyshortcuts={mac ? "Meta+b" : "Control+b"}
        onClick={onToggleSidebar}
      >
        <PanelLeft className={sidebarVisible ? "text-foreground/70" : "text-muted-foreground/60"} />
      </Button>
      <Button
        variant="ghost"
        size="icon-xs"
        aria-label={t("toggle_panel")}
        title={t("toggle_panel")}
        aria-pressed={bottomPanelVisible}
        aria-keyshortcuts={mac ? "Meta+j" : "Control+j"}
        onClick={onTogglePanel}
      >
        <PanelBottom className={bottomPanelVisible ? "text-foreground/70" : "text-muted-foreground/60"} />
      </Button>
      <Button
        variant="ghost"
        size="icon-xs"
        aria-label={t("reset_workspace")}
        title={t("reset_workspace")}
        onClick={onResetLayout}
      >
        <RotateCcw className="text-muted-foreground/60" />
      </Button>
    </div>
  );
}

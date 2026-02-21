import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { useMutation } from "@tanstack/react-query";
import {
  PanelBottomClose,
  PanelBottomOpen,
  RefreshCw,
  XCircle,
  Unplug,
  Circle,
  Loader2,
  CircleAlert,
} from "lucide-react";

import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import { Status, useSession } from "@/context/SessionContext";

interface StatusBarProps {
  bottomPanelVisible: boolean;
  setBottomPanelVisible: (visible: boolean) => void;
}

export function StatusBar({
  bottomPanelVisible,
  setBottomPanelVisible,
}: StatusBarProps) {
  const { t } = useTranslation();
  const { status, device, pid } = useSession();
  const navigate = useNavigate();

  const getStatusColor = () => {
    switch (status) {
      case Status.Ready:
        return "bg-green-600 dark:bg-green-900";
      case Status.Disconnected:
        return "bg-orange-500 dark:bg-orange-900";
      case Status.Connecting:
      default:
        return "bg-muted text-muted-foreground";
    }
  };

  const getStatusIcon = () => {
    switch (status) {
      case Status.Ready:
        return <Circle className="w-3 h-3 fill-current" />;
      case Status.Disconnected:
        return <CircleAlert className="w-3 h-3" />;
      case Status.Connecting:
      default:
        return <Loader2 className="w-3 h-3 animate-spin" />;
    }
  };

  const handleReloadPage = () => {
    window.location.reload();
  };

  const killProcessMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch(`/api/device/${device}/kill/${pid}`, { method: "POST" });
      if (!res.ok) throw new Error("Failed to kill process");
    },
    onSuccess: () => {
      navigate(`/list/${device}/apps`);
    },
  });

  const handleKillProcess = () => {
    if (!device || !pid) return;
    killProcessMutation.mutate();
  };

  const handleDetach = () => {
    if (device) {
      navigate(`/list/${device}/apps`);
    }
  };

  return (
    <footer
      className={`${getStatusColor()} px-4 py-1 text-sm text-white flex items-center justify-between`}
    >
      <DropdownMenu>
        <DropdownMenuTrigger
          render={
            <button
              type="button"
              className="hover:bg-white/20 px-1 py-0.5 rounded transition-colors cursor-pointer flex items-center gap-1.5"
            />
          }
        >
          {getStatusIcon()}
          {status === Status.Ready && t("connected")}
          {status === Status.Connecting && t("connecting")}
          {status === Status.Disconnected && t("disconnected")}
        </DropdownMenuTrigger>
        <DropdownMenuContent align="start">
          <DropdownMenuItem onClick={handleReloadPage}>
            <RefreshCw className="w-4 h-4 mr-2" />
            {t("reload_page")}
          </DropdownMenuItem>
          <DropdownMenuItem
            onClick={handleKillProcess}
            disabled={status !== Status.Ready}
          >
            <XCircle className="w-4 h-4 mr-2" />
            {t("kill_process")}
          </DropdownMenuItem>
          <DropdownMenuItem onClick={handleDetach}>
            <Unplug className="w-4 h-4 mr-2" />
            {t("detach")}
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
      <button
        type="button"
        onClick={() => setBottomPanelVisible(!bottomPanelVisible)}
        className="p-0.5 hover:bg-white/20 rounded transition-colors"
        title={bottomPanelVisible ? t("hide_panel") : t("show_panel")}
      >
        {bottomPanelVisible ? (
          <PanelBottomClose className="w-4 h-4" />
        ) : (
          <PanelBottomOpen className="w-4 h-4" />
        )}
      </button>
    </footer>
  );
}

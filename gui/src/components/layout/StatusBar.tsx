import { useTranslation } from "react-i18next";
import { useNavigate } from "react-router";
import { useMutation } from "@tanstack/react-query";
import {
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

export function StatusBar() {
  const { t } = useTranslation();
  const { status, device, pid, platform } = useSession();
  const navigate = useNavigate();
  const getStatusClass = () => {
    switch (status) {
      case Status.Ready:
        return "text-emerald-600 dark:text-emerald-400";
      case Status.Disconnected:
        return "text-orange-600 dark:text-orange-400";
      case Status.Connecting:
      default:
        return "text-muted-foreground";
    }
  };

  const getStatusIcon = () => {
    switch (status) {
      case Status.Ready:
        return <Circle className="h-2.5 w-2.5 fill-current" />;
      case Status.Disconnected:
        return <CircleAlert className="h-3.5 w-3.5" />;
      case Status.Connecting:
      default:
        return <Loader2 className="h-3.5 w-3.5 animate-spin" />;
    }
  };

  const handleReloadPage = () => {
    window.location.reload();
  };

  const killProcessMutation = useMutation({
    mutationFn: async () => {
      const res = await fetch(`/api/device/${device}/kill/${pid}`, {
        method: "POST",
      });
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
      className="native-chrome flex h-6 shrink-0 items-center justify-between border-t border-border bg-sidebar px-2 text-[11px] text-muted-foreground"
    >
      <div className="flex items-center gap-1">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <button
                type="button"
                className="flex h-5 items-center gap-1.5 rounded px-1 text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
              />
            }
          >
            <span className={getStatusClass()}>{getStatusIcon()}</span>
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
        {status === Status.Disconnected && (
          <button
            type="button"
            onClick={handleReloadPage}
            className="flex h-5 items-center gap-1 rounded px-1 text-muted-foreground outline-none hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
          >
            <RefreshCw className="w-3 h-3" />
            {t("reload")}
          </button>
        )}
      </div>
      <div className="flex items-center gap-3 px-1">
        {platform && <span>{platform === "fruity" ? "iOS" : "Android"}</span>}
        {pid && <span className="tabular-nums">PID {pid}</span>}
      </div>
    </footer>
  );
}

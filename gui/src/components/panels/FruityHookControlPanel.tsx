import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Database,
  Loader2,
  Clipboard,
  Fingerprint,
  Smartphone,
  FolderOpen,
} from "lucide-react";

import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useSession, Status } from "@/context/SessionContext";
import { useFruityQuery } from "@/lib/queries";
import { FruityUserHooksList } from "./FruityUserHooksList";

interface PinInfo {
  id: string;
  active: boolean;
  available: boolean;
}

interface HookGroup {
  id: string;
  icon: React.ReactNode;
  nameKey: string;
  descKey: string;
}

const HOOK_GROUPS: HookGroup[] = [
  {
    id: "sqlite",
    icon: <Database className="h-4 w-4" />,
    nameKey: "hook_sqlite",
    descKey: "hook_sqlite_desc",
  },
  {
    id: "pasteboard",
    icon: <Clipboard className="h-4 w-4" />,
    nameKey: "hook_pasteboard",
    descKey: "hook_pasteboard_desc",
  },
  {
    id: "deviceid",
    icon: <Smartphone className="h-4 w-4" />,
    nameKey: "hook_deviceid",
    descKey: "hook_deviceid_desc",
  },
  {
    id: "biometric",
    icon: <Fingerprint className="h-4 w-4" />,
    nameKey: "hook_biometric",
    descKey: "hook_biometric_desc",
  },
  {
    id: "fileops",
    icon: <FolderOpen className="h-4 w-4" />,
    nameKey: "hook_fileops",
    descKey: "hook_fileops_desc",
  },
];

export function FruityHookControlPanel() {
  const { t } = useTranslation();
  const { fruity, status } = useSession();
  const [hookStatus, setHookStatus] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  // Fetch pin status from agent via pins.list() RPC
  const { data: pinList, isLoading: isLoadingStatus } = useFruityQuery<PinInfo[]>(
    ["pinsList"],
    (api) => api.pins.list(),
  );

  // Update local state when pin list is fetched
  useEffect(() => {
    if (pinList) {
      const statusMap: Record<string, boolean> = {};
      for (const pin of pinList) {
        statusMap[pin.id] = pin.active;
      }
      setHookStatus(statusMap);
    }
  }, [pinList]);

  const handleToggle = async (groupId: string, enabled: boolean) => {
    if (!fruity) return;

    setLoading((prev) => ({ ...prev, [groupId]: true }));

    try {
      if (enabled) {
        await fruity.pins.start(groupId);
      } else {
        await fruity.pins.stop(groupId);
      }
      setHookStatus((prev) => ({ ...prev, [groupId]: enabled }));
    } catch (error) {
      console.error(
        `Failed to ${enabled ? "start" : "stop"} hook group ${groupId}:`,
        error,
      );
    } finally {
      setLoading((prev) => ({ ...prev, [groupId]: false }));
    }
  };

  const isDisabled = status !== Status.Ready;

  if (isLoadingStatus) {
    return (
      <div className="p-3 space-y-4">
        <Skeleton className="h-5 w-20" />
        <div className="space-y-3">
          <Skeleton className="h-3 w-24" />
          {Array.from({ length: 5 }).map((_, i) => (
            <div key={i} className="flex items-start space-x-3 p-2">
              <Skeleton className="h-4 w-4 rounded shrink-0 mt-0.5" />
              <div className="flex-1 space-y-1.5">
                <div className="flex items-center justify-between">
                  <Skeleton className="h-4 w-28" />
                  <Skeleton className="h-5 w-9 rounded-full" />
                </div>
                <Skeleton className="h-3 w-full" />
              </div>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="p-3 space-y-4">
      <h2 className="text-base font-semibold">{t("hooks")}</h2>

      {/* Built-in Hooks Section */}
      <div className="space-y-3">
        <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
          {t("hook_builtin")}
        </h3>
        <div className="space-y-3">
          {HOOK_GROUPS.map((group) => (
            <div
              key={group.id}
              className="flex items-start space-x-3 p-2 rounded-md hover:bg-muted/50 transition-colors"
            >
              <div className="shrink-0 mt-0.5 text-muted-foreground">
                {group.icon}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between">
                  <Label
                    htmlFor={`hook-${group.id}`}
                    className="text-sm font-medium cursor-pointer"
                  >
                    {t(group.nameKey)}
                  </Label>
                  {loading[group.id] ? (
                    <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                  ) : (
                    <Switch
                      id={`hook-${group.id}`}
                      checked={hookStatus[group.id] || false}
                      onCheckedChange={(checked) =>
                        handleToggle(group.id, checked)
                      }
                      disabled={isDisabled}
                    />
                  )}
                </div>
                <p className="text-sm text-muted-foreground mt-1 leading-relaxed">
                  {t(group.descKey)}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* User Defined Hooks Section */}
      <div className="space-y-3">
        <h3 className="text-sm font-medium text-muted-foreground uppercase tracking-wide">
          {t("hook_user_defined")}
        </h3>
        <FruityUserHooksList />
      </div>
    </div>
  );
}

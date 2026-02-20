import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Loader2,
  Clipboard,
  Radio,
  Send,
  FileKey,
} from "lucide-react";

import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { useSession, Status } from "@/context/SessionContext";
import { useDroidRpcQuery } from "@/lib/queries";

interface TapInfo {
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
    id: "clipboard",
    icon: <Clipboard className="h-4 w-4" />,
    nameKey: "hook_clipboard",
    descKey: "hook_clipboard_desc",
  },
  {
    id: "broadcast",
    icon: <Radio className="h-4 w-4" />,
    nameKey: "hook_broadcast",
    descKey: "hook_broadcast_desc",
  },
  {
    id: "intent",
    icon: <Send className="h-4 w-4" />,
    nameKey: "hook_intent",
    descKey: "hook_intent_desc",
  },
  {
    id: "sharedpref",
    icon: <FileKey className="h-4 w-4" />,
    nameKey: "hook_sharedpref",
    descKey: "hook_sharedpref_desc",
  },
];

export function DroidHookControlPanel() {
  const { t } = useTranslation();
  const { droid, status } = useSession();
  const [hookStatus, setHookStatus] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  const { data: tapList, isLoading: isLoadingStatus } = useDroidRpcQuery<TapInfo[]>(
    ["tapsList"],
    (api) => api.taps.list(),
  );

  useEffect(() => {
    if (tapList) {
      const statusMap: Record<string, boolean> = {};
      for (const tap of tapList) {
        statusMap[tap.id] = tap.active;
      }
      setHookStatus(statusMap);
    }
  }, [tapList]);

  const handleToggle = async (groupId: string, enabled: boolean) => {
    if (!droid) return;

    setLoading((prev) => ({ ...prev, [groupId]: true }));

    try {
      if (enabled) {
        await droid.taps.start(groupId);
      } else {
        await droid.taps.stop(groupId);
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
          {Array.from({ length: 4 }).map((_, i) => (
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

      <div className="space-y-3">
        <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
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
                <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                  {t(group.descKey)}
                </p>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

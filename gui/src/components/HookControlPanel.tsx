import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Lock, Database, Loader2 } from "lucide-react";

import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { useSession, Status } from "@/context/SessionContext";

interface HookGroup {
  id: string;
  icon: React.ReactNode;
  nameKey: string;
  descKey: string;
}

const HOOK_GROUPS: HookGroup[] = [
  {
    id: "crypto",
    icon: <Lock className="h-4 w-4" />,
    nameKey: "hook_crypto",
    descKey: "hook_crypto_desc",
  },
  {
    id: "sqlite",
    icon: <Database className="h-4 w-4" />,
    nameKey: "hook_sqlite",
    descKey: "hook_sqlite_desc",
  },
];

export function HookControlPanel() {
  const { t } = useTranslation();
  const { fruity, status } = useSession();
  const [hookStatus, setHookStatus] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});

  // Fetch initial hook status
  useEffect(() => {
    if (status !== Status.Ready || !fruity) return;

    fruity.hook
      .status()
      .then((status) => {
        setHookStatus(status);
      })
      .catch(console.error);
  }, [fruity, status]);

  const handleToggle = async (groupId: string, enabled: boolean) => {
    if (!fruity) return;

    setLoading((prev) => ({ ...prev, [groupId]: true }));

    try {
      if (enabled) {
        await fruity.hook.start(groupId);
      } else {
        await fruity.hook.stop(groupId);
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

  return (
    <div className="p-3 space-y-4">
      <h2 className="text-base font-semibold">{t("hooks")}</h2>

      {/* Built-in Hooks Section */}
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

      {/* User Defined Hooks Section */}
      <div className="space-y-3">
        <h3 className="text-xs font-medium text-muted-foreground uppercase tracking-wide">
          {t("hook_user_defined")}
        </h3>
        <p className="text-xs text-muted-foreground italic">
          {t("feature_coming_soon")}
        </p>
      </div>
    </div>
  );
}

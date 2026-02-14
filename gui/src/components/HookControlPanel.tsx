import { useEffect, useState, useCallback, useRef } from "react";
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
import { useSession, Status, Mode } from "@/context/SessionContext";
import { useRpcQuery } from "@/lib/queries";
import { UserHooksList } from "./UserHooksList";

const HOOKS_STORAGE_PREFIX = "igf:hooks:";

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

export function HookControlPanel() {
  const { t } = useTranslation();
  const { fruity, status, device, bundle, pid, mode } = useSession();
  const [hookStatus, setHookStatus] = useState<Record<string, boolean>>({});
  const [loading, setLoading] = useState<Record<string, boolean>>({});
  const restoredRef = useRef(false);

  // Generate storage key based on device and identifier
  const getStorageKey = useCallback(() => {
    if (!device) return null;
    if (mode === Mode.App && bundle) {
      return `${HOOKS_STORAGE_PREFIX}${device}|${bundle}`;
    } else if (mode === Mode.Daemon && pid) {
      // For daemon mode, use pid (note: pid changes between launches)
      return `${HOOKS_STORAGE_PREFIX}${device}|pid-${pid}`;
    }
    return null;
  }, [device, bundle, pid, mode]);

  // Load saved hooks from localStorage
  const loadSavedHooks = useCallback((): string[] => {
    const key = getStorageKey();
    if (!key) return [];
    try {
      const saved = localStorage.getItem(key);
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  }, [getStorageKey]);

  // Save hooks to localStorage
  const saveHooks = useCallback((enabledHooks: string[]) => {
    const key = getStorageKey();
    if (!key) return;
    try {
      localStorage.setItem(key, JSON.stringify(enabledHooks));
    } catch {
      // ignore storage errors
    }
  }, [getStorageKey]);

  // Fetch initial hook status using TanStack Query
  const { data: initialStatus } = useRpcQuery<Record<string, boolean>>(
    ["hookStatus", device ?? "", bundle ?? "", String(pid ?? "")],
    (api) => api.hook.status()
  );

  // Update local state when initial status is fetched
  useEffect(() => {
    if (initialStatus) {
      setHookStatus(initialStatus);
    }
  }, [initialStatus]);

  // Restore saved hooks after initial status is loaded
  useEffect(() => {
    if (!initialStatus || !fruity || restoredRef.current) return;

    const restoreSavedHooks = async () => {
      restoredRef.current = true;

      const savedHooks = loadSavedHooks();
      for (const groupId of savedHooks) {
        if (!initialStatus[groupId]) {
          setLoading((prev) => ({ ...prev, [groupId]: true }));
          try {
            await fruity.hook.start(groupId);
            setHookStatus((prev) => ({ ...prev, [groupId]: true }));
          } catch (error) {
            console.error(`Failed to restore hook group ${groupId}:`, error);
          } finally {
            setLoading((prev) => ({ ...prev, [groupId]: false }));
          }
        }
      }
    };

    restoreSavedHooks();
  }, [initialStatus, fruity, loadSavedHooks]);

  // Reset restored flag when session changes
  useEffect(() => {
    restoredRef.current = false;
  }, [device, bundle, pid]);

  const handleToggle = async (groupId: string, enabled: boolean) => {
    if (!fruity) return;

    setLoading((prev) => ({ ...prev, [groupId]: true }));

    try {
      if (enabled) {
        await fruity.hook.start(groupId);
      } else {
        await fruity.hook.stop(groupId);
      }
      setHookStatus((prev) => {
        const newStatus = { ...prev, [groupId]: enabled };
        // Save enabled hooks to localStorage
        const enabledHooks = Object.entries(newStatus)
          .filter(([, v]) => v)
          .map(([k]) => k);
        saveHooks(enabledHooks);
        return newStatus;
      });
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
        <UserHooksList />
      </div>
    </div>
  );
}

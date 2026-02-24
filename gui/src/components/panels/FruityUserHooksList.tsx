import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Trash2, Loader2 } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useSession, Status } from "@/context/SessionContext";
import { formatObjCMethod } from "@/lib/codegen/hookjs";
import { useFruityQuery } from "@/lib/queries";

interface UserHook {
  type: "objc" | "native";
  module?: string | null;
  cls?: string;
  name: string;
}

export function FruityUserHooksList() {
  const { t } = useTranslation();
  const { fruity, status } = useSession();
  const [removingHook, setRemovingHook] = useState<string | null>(null);

  const {
    data: hooks = [],
    isLoading: loading,
    refetch,
  } = useFruityQuery<UserHook[]>(["userHooks"], (api) => api.hook.userHooks());

  // Listen for hooks:refresh event to reload the list
  useEffect(() => {
    const handleRefresh = () => {
      refetch();
    };
    window.addEventListener("hooks:refresh", handleRefresh);
    return () => window.removeEventListener("hooks:refresh", handleRefresh);
  }, [refetch]);

  const getHookKey = (hook: UserHook): string => {
    if (hook.type === "objc") {
      return `objc:${hook.cls}:${hook.name}`;
    }
    return `native:${hook.module || "null"}:${hook.name}`;
  };

  const getHookLabel = (hook: UserHook): string => {
    if (hook.type === "objc" && hook.cls) {
      return formatObjCMethod(hook.cls, hook.name);
    }
    return hook.module ? `${hook.module}!${hook.name}` : hook.name;
  };

  const handleRemove = async (hook: UserHook) => {
    if (!fruity) return;

    const key = getHookKey(hook);
    setRemovingHook(key);

    try {
      if (hook.type === "objc" && hook.cls) {
        await fruity.objc.unswizzle(hook.cls, hook.name);
      } else if (hook.type === "native") {
        await fruity.native.unhook(hook.module ?? null, hook.name);
      }
      // Refresh the list
      await refetch();
    } catch (error) {
      console.error("Failed to remove hook:", error);
    } finally {
      setRemovingHook(null);
    }
  };

  const isDisabled = status !== Status.Ready;

  // Group hooks by type
  const objcHooks = hooks.filter((h) => h.type === "objc");
  const nativeHooks = hooks.filter((h) => h.type === "native");

  if (loading) {
    return (
      <div className="flex items-center justify-center py-4">
        <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (hooks.length === 0) {
    return (
      <p className="text-xs text-muted-foreground italic">
        {t("hook_user_no_hooks")}
      </p>
    );
  }

  const renderHookItem = (hook: UserHook) => {
    const key = getHookKey(hook);
    const isRemoving = removingHook === key;

    return (
      <div
        key={key}
        className="flex items-center justify-between p-2 rounded-md hover:bg-muted/50 transition-colors group"
      >
        <div className="flex-1 min-w-0">
          <div
            className="font-mono text-xs truncate"
            title={getHookLabel(hook)}
          >
            {getHookLabel(hook)}
          </div>
        </div>
        <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6 text-destructive hover:text-destructive"
            onClick={() => handleRemove(hook)}
            disabled={isRemoving || isDisabled}
            title={t("hook_remove")}
          >
            {isRemoving ? (
              <Loader2 className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Trash2 className="h-3.5 w-3.5" />
            )}
          </Button>
        </div>
      </div>
    );
  };

  return (
    <div className="space-y-3">
      {objcHooks.length > 0 && (
        <div>
          <div className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1">
            Objective-C ({objcHooks.length})
          </div>
          <div className="space-y-1">{objcHooks.map(renderHookItem)}</div>
        </div>
      )}

      {nativeHooks.length > 0 && (
        <div>
          <div className="text-[10px] font-medium text-muted-foreground uppercase tracking-wide mb-1">
            {t("hook_native")} ({nativeHooks.length})
          </div>
          <div className="space-y-1">{nativeHooks.map(renderHookItem)}</div>
        </div>
      )}
    </div>
  );
}

import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Search, EllipsisVertical, ArrowDownToLine, ArrowUpFromLine } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";

import { useDock } from "@/context/DockContext";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuSeparator,
} from "@/components/ui/dropdown-menu";
import { Platform, useSession } from "@/context/SessionContext";
import { usePlatformQuery } from "@/lib/queries";
import type { ModuleInfo } from "@agent/common/symbol";

const ITEM_HEIGHT = 72;

export function ModulesPanel() {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const { platform, device, pid } = useSession();
  const isDroid = platform === Platform.Droid;
  const [search, setSearch] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data: modules = [], isLoading } = usePlatformQuery(
    ["modules"],
    (api) => api.symbol.modules(),
  );

  const filteredModules = useMemo(() => {
    if (!search.trim()) return modules;
    const query = search.toLowerCase();
    return modules.filter(
      (m) =>
        m.name.toLowerCase().includes(query) ||
        m.path.toLowerCase().includes(query),
    );
  }, [modules, search]);

  const virtualizer = useVirtualizer({
    count: filteredModules.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ITEM_HEIGHT,
  });

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 space-y-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="text-xs text-muted-foreground">
          {filteredModules.length} / {modules.length}
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 min-h-0 h-full overflow-auto">
        {isLoading ? (
          <div className="px-4 space-y-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="space-y-1.5">
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-3 w-64" />
                <Skeleton className="h-3 w-80" />
              </div>
            ))}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((vItem) => {
              const mod = filteredModules[vItem.index];
              return (
                <ModuleRow
                  key={vItem.key}
                  mod={mod}
                  style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
                  openFilePanel={openFilePanel}
                  isDroid={isDroid}
                  device={device}
                  pid={pid}
                />
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

function ModuleRow({
  mod,
  style,
  openFilePanel,
  isDroid,
  device,
  pid,
}: {
  mod: ModuleInfo;
  style: React.CSSProperties;
  isDroid: boolean;
  device: string | undefined;
  pid: number | undefined;
  openFilePanel: (panel: {
    id: string;
    component: string;
    title: string;
    params: { path: string };
  }) => void;
}) {
  const { t } = useTranslation();

  const openModuleView = (component: string, suffix: string) => {
    openFilePanel({
      id: `module_${mod.base}_${component}`,
      component,
      title: `${mod.name} - ${suffix}`,
      params: { path: mod.path },
    });
  };

  return (
    <div
      className="absolute left-0 right-0 group px-4 py-2 border-b border-border hover:bg-accent"
      style={style}
    >
      <div className="flex items-start justify-between">
        <button
          type="button"
          className="text-sm font-medium truncate text-left text-amber-600 dark:text-amber-400 hover:underline cursor-pointer"
          onClick={() => openModuleView("moduleExported", t("exports"))}
        >
          {mod.name}
        </button>
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <Button
                variant="ghost"
                size="icon"
                className="h-6 w-6 shrink-0"
              />
            }
          >
            <EllipsisVertical className="h-4 w-4" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-40">
            <DropdownMenuItem onClick={() => openModuleView("moduleImports", t("imports"))}>
              <ArrowDownToLine className="h-4 w-4" />
              {t("imports")}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => openModuleView("moduleExported", t("exports"))}>
              <ArrowUpFromLine className="h-4 w-4" />
              {t("exports")}
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => openModuleView("moduleSymbols", t("symbols"))}>
              <span className="h-4 w-4" />
              {t("symbols")}
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem onClick={() => openModuleView("moduleSections", t("sections"))}>
              <span className="h-4 w-4" />
              {t("sections")}
            </DropdownMenuItem>
            {!isDroid && (
              <DropdownMenuItem onClick={() => openModuleView("moduleClasses", t("classes"))}>
                <span className="h-4 w-4" />
                {t("classes")}
              </DropdownMenuItem>
            )}
            {!isDroid && (
              <>
                <DropdownMenuSeparator />
                <DropdownMenuItem onClick={async () => {
                  const url = `/api/dump/${device}/${pid}?path=${encodeURIComponent(mod.path)}`;
                  const res = await fetch(url, { method: "HEAD" });
                  if (res.ok) {
                    location.replace(url);
                  } else {
                    toast.warning(t("dump_decrypted_error"));
                  }
                }}>
                  <span className="h-4 w-4" />
                  {t("dump_decrypted")}
                </DropdownMenuItem>
              </>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <div className="text-xs text-muted-foreground font-mono truncate">
        {mod.base.toLowerCase()}-
        {"0x" + (parseInt(mod.base, 16) + mod.size).toString(16).toLowerCase()}
      </div>
      <div className="text-xs text-muted-foreground truncate">{mod.path}</div>
    </div>
  );
}

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { List, type RowComponentProps } from "react-window";

import { useDock } from "@/context/DockContext";
import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { usePlatformRpcQuery } from "@/lib/queries";
import type { ModuleInfo } from "@agent/common/symbol";

const ITEM_HEIGHT = 72;

export function ModulesPanel() {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const [search, setSearch] = useState("");

  const { data: modules = [], isLoading } = usePlatformRpcQuery(
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
      <div className="flex-1 min-h-0 h-full">
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
          <div className="flex h-full">
            <List
              rowComponent={ModuleRow}
              rowCount={filteredModules.length}
              rowHeight={ITEM_HEIGHT}
              rowProps={{ modules: filteredModules, openFilePanel }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function ModuleRow({
  index,
  style,
  modules,
  openFilePanel,
}: RowComponentProps<{
  modules: ModuleInfo[];
  openFilePanel: (panel: {
    id: string;
    component: string;
    title: string;
    params: { path: string };
  }) => void;
}>) {
  const mod = modules[index];

  return (
    <div
      className="px-4 py-2 border-b border-border hover:bg-accent"
      style={style}
    >
      <button
        type="button"
        className="text-sm font-medium truncate text-left w-full text-amber-600 dark:text-amber-400 hover:underline cursor-pointer"
        onClick={() =>
          openFilePanel({
            id: `module_${mod.base}`,
            component: "moduleDetail",
            title: mod.name,
            params: {
              path: mod.path,
            },
          })
        }
      >
        {mod.name}
      </button>
      <div className="text-xs text-muted-foreground font-mono truncate">
        {mod.base.toLowerCase()}-
        {"0x" + (parseInt(mod.base, 16) + mod.size).toString(16).toLowerCase()}
      </div>
      <div className="text-xs text-muted-foreground truncate">{mod.path}</div>
    </div>
  );
}

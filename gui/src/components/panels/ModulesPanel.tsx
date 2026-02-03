import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { List, type RowComponentProps } from "react-window";

import { useDock } from "@/context/DockContext";
import { Input } from "@/components/ui/input";
import { useRpcQuery } from "@/lib/queries";
import type { ModuleInfo } from "../../../../agent/types/fruity/modules/symbol";

const ITEM_HEIGHT = 72;

export function ModulesPanel() {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const [search, setSearch] = useState("");

  const { data: modules = [], isLoading } = useRpcQuery(
    ["modules"],
    (api) => api.symbol.modules()
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
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        <div className="text-xs text-gray-500">
          {filteredModules.length} / {modules.length}
        </div>
      </div>
      <div className="flex-1 min-h-0 h-full">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {t("loading")}...
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
      className="px-4 py-2 border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800"
      style={style}
    >
      <button
        type="button"
        className="text-sm font-medium truncate text-left w-full text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
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
      <div className="text-xs text-gray-500 font-mono truncate">
        {mod.base.toLowerCase()}-
        {"0x" + (parseInt(mod.base, 16) + mod.size).toString(16).toLowerCase()}
      </div>
      <div className="text-xs text-gray-400 truncate">{mod.path}</div>
    </div>
  );
}

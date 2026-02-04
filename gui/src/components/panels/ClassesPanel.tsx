import { useMemo, useState } from "react";
import { useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { List, type RowComponentProps } from "react-window";

import { Input } from "@/components/ui/input";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { useDock } from "@/context/DockContext";
import { useRpcQuery } from "@/lib/queries";

const ITEM_HEIGHT = 32;

type ScopeType = "__main__" | "__app__" | "__global__";

export function ClassesPanel() {
  const { t } = useTranslation();
  const { mode } = useParams();
  const { openFilePanel } = useDock();
  const isDaemon = mode === "daemon";
  const [scope, setScope] = useState<ScopeType>(isDaemon ? "__main__" : "__app__");
  const [search, setSearch] = useState("");

  const { data: classes = [], isLoading } = useRpcQuery(
    ["classes", scope],
    (api) => api.classdump.list(scope) as Promise<string[]>
  );

  const filteredClasses = useMemo(() => {
    if (!search.trim()) return classes;
    const query = search.toLowerCase();
    return classes.filter((c) => c.toLowerCase().includes(query));
  }, [classes, search]);

  const handleScopeChange = (value: string) => {
    if (value) setScope(value as ScopeType);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 space-y-4">
        <ToggleGroup
          type="single"
          value={scope}
          onValueChange={handleScopeChange}
          variant="outline"
          size="sm"
          className="w-full"
        >
          <ToggleGroupItem value="__main__" className="flex-1">{t("main")}</ToggleGroupItem>
          {!isDaemon && (
            <ToggleGroupItem value="__app__" className="flex-1">{t("app")}</ToggleGroupItem>
          )}
          <ToggleGroupItem value="__global__" className="flex-1">{t("global")}</ToggleGroupItem>
        </ToggleGroup>
        {!isLoading && (
          <>
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
              {filteredClasses.length} / {classes.length}
            </div>
          </>
        )}
      </div>
      <div className="flex-1 min-h-0 h-full">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-600" />
          </div>
        ) : (
          <div className="flex h-full">
            <List
              rowComponent={ClassRow}
              rowCount={filteredClasses.length}
              rowHeight={ITEM_HEIGHT}
              rowProps={{ classes: filteredClasses, openFilePanel }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function ClassRow({
  index,
  style,
  classes,
  openFilePanel,
}: RowComponentProps<{
  classes: string[];
  openFilePanel: (panel: {
    id: string;
    component: string;
    title: string;
    params: { className: string };
  }) => void;
}>) {
  const className = classes[index];

  return (
    <div
      className="px-4 py-1 border-b border-gray-200 dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-800"
      style={style}
    >
      <button
        type="button"
        className="text-sm font-mono truncate block text-left w-full text-blue-600 dark:text-blue-400 hover:underline cursor-pointer"
        onClick={() =>
          openFilePanel({
            id: `class_${className}`,
            component: "classDetail",
            title: className,
            params: { className },
          })
        }
      >
        {className}
      </button>
    </div>
  );
}

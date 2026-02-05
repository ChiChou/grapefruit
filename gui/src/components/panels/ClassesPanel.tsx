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
      <div className="p-3 space-y-3 border-b border-border/50">
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
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder={t("search")}
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9 h-8 text-sm"
              />
            </div>
            <div className="text-xs text-muted-foreground">
              {filteredClasses.length.toLocaleString()} / {classes.length.toLocaleString()} {t("items")}
            </div>
          </>
        )}
      </div>
      <div className="flex-1 min-h-0 h-full overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("loading")}...
          </div>
        ) : filteredClasses.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            {t("no_results")}
          </div>
        ) : (
          <List
            rowComponent={ClassRow}
            rowCount={filteredClasses.length}
            rowHeight={ITEM_HEIGHT}
            rowProps={{ classes: filteredClasses, openFilePanel }}
          />
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

  // Split class name into prefix and name for better visual hierarchy
  const dotIndex = className.lastIndexOf(".");
  const hasPrefix = dotIndex > 0;
  const prefix = hasPrefix ? className.slice(0, dotIndex) : null;
  const name = hasPrefix ? className.slice(dotIndex + 1) : className;

  return (
    <div
      className="px-3 py-1.5 border-b border-border/50 hover:bg-accent/50 transition-colors"
      style={style}
    >
      <button
        type="button"
        className="flex items-center gap-2 w-full text-left cursor-pointer group"
        onClick={() =>
          openFilePanel({
            id: `class_${className}`,
            component: "classDetail",
            title: className,
            params: { className },
          })
        }
      >
        {prefix && (
          <span className="text-xs text-muted-foreground/70 font-medium shrink-0">
            {prefix}.
          </span>
        )}
        <span className="text-sm font-mono truncate text-foreground group-hover:text-primary transition-colors">
          {name}
        </span>
      </button>
    </div>
  );
}

import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { List, type RowComponentProps } from "react-window";

import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useDock } from "@/context/DockContext";
import { useDroidRpcQuery } from "@/lib/queries";

const ITEM_HEIGHT = 32;

export function DroidClassesPanel() {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const [search, setSearch] = useState("");

  const { data: classes = [], isLoading } = useDroidRpcQuery(
    ["classes"],
    (api) => api.classes.list() as Promise<string[]>
  );

  const filteredClasses = useMemo(() => {
    if (!search.trim()) return classes;
    const query = search.toLowerCase();
    return classes.filter((c) => c.toLowerCase().includes(query));
  }, [classes, search]);

  return (
    <div className="h-full flex flex-col">
      <div className="p-3 space-y-3 border-b border-border/50">
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
          <div className="px-3 py-1.5 space-y-2">
            {Array.from({ length: 16 }).map((_, i) => (
              <Skeleton key={i} className="h-5" style={{ width: `${40 + (i * 17) % 50}%` }} />
            ))}
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

  return (
    <div
      className="px-3 py-1.5 border-b border-border/50 hover:bg-accent/50 transition-colors"
      style={style}
    >
      <button
        type="button"
        className="text-sm font-mono truncate text-foreground hover:text-primary transition-colors w-full text-left cursor-pointer"
        onClick={() =>
          openFilePanel({
            id: `javaclass_${className}`,
            component: "javaClassDetail",
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

import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";

import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { useDock } from "@/context/DockContext";
import { useDroidQuery } from "@/lib/queries";

const ITEM_HEIGHT = 32;

export function DroidClassesPanel() {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const [search, setSearch] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data: classes = [], isLoading } = useDroidQuery(
    ["classes"],
    (api) => api.classes.list() as Promise<string[]>
  );

  const filteredClasses = useMemo(() => {
    if (!search.trim()) return classes;
    const query = search.toLowerCase();
    return classes.filter((c) => c.toLowerCase().includes(query));
  }, [classes, search]);

  const virtualizer = useVirtualizer({
    count: filteredClasses.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ITEM_HEIGHT,
  });

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
      <div ref={scrollRef} className="flex-1 min-h-0 h-full overflow-auto">
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
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((vItem) => {
              const className = filteredClasses[vItem.index];
              return (
                <div
                  key={vItem.key}
                  className="absolute left-0 right-0 px-3 py-1.5 border-b border-border/50 hover:bg-accent/50 transition-colors"
                  style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
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
            })}
          </div>
        )}
      </div>
    </div>
  );
}

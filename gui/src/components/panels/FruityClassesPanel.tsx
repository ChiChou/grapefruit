import { useMemo, useRef, useState } from "react";
import { useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { Search, FileCode } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";

import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Button } from "@/components/ui/button";
import { useDock } from "@/context/DockContext";
import { useFruityQuery } from "@/lib/queries";

const ITEM_HEIGHT = 32;

type ScopeType = "__main__" | "__app__" | "__global__";

export function FruityClassesPanel() {
  const { t } = useTranslation();
  const { mode } = useParams();
  const { openFilePanel } = useDock();
  const isDaemon = mode === "daemon";
  const [scope, setScope] = useState<ScopeType>(isDaemon ? "__main__" : "__app__");
  const [search, setSearch] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data: classes = [], isLoading } = useFruityQuery(
    ["classes", scope],
    (api) => api.classdump.list(scope) as Promise<string[]>
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

  const handleScopeChange = (value: string) => {
    if (value) setScope(value as ScopeType);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-3 space-y-3 border-b border-border/50">
        <ToggleGroup
          value={[scope]}
          onValueChange={(values) => {
            const last = values[values.length - 1];
            if (last) handleScopeChange(last);
          }}
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
                  className="absolute left-0 right-0 px-3 py-1.5 border-b border-border/50 hover:bg-accent/50 transition-colors group flex items-center"
                  style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
                >
                  <button
                    type="button"
                    className="text-sm font-mono truncate text-foreground/80 hover:text-primary transition-colors flex-1 text-left cursor-pointer"
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
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-6 w-6 shrink-0 text-muted-foreground"
                    title="classdump"
                    onClick={() =>
                      openFilePanel({
                        id: `classdump_${className}`,
                        component: "classDump",
                        title: `Classdump - ${className}`,
                        params: { className },
                      })
                    }
                  >
                    <FileCode className="h-3.5 w-3.5" />
                  </Button>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

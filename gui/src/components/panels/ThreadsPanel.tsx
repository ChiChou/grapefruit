import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search, RefreshCw } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { usePlatformQuery } from "@/lib/queries";

const ITEM_HEIGHT = 52;

const STATE_COLORS: Record<string, string> = {
  waiting: "bg-yellow-100 text-yellow-700 dark:bg-yellow-900/30 dark:text-yellow-400",
  suspended: "bg-orange-100 text-orange-700 dark:bg-orange-900/30 dark:text-orange-400",
  running: "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
  stopped: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
  halted: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
};

export function ThreadsPanel() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data: threads = [], isLoading, refetch, isFetching } = usePlatformQuery(
    ["threads"],
    (api) => api.threads.list(),
  );

  const filtered = useMemo(() => {
    if (!search.trim()) return threads;
    const q = search.toLowerCase();
    return threads.filter(
      (t) =>
        String(t.id).includes(q) ||
        (t.name?.toLowerCase().includes(q) ?? false) ||
        (t.symbol?.toLowerCase().includes(q) ?? false) ||
        (t.moduleName?.toLowerCase().includes(q) ?? false),
    );
  }, [threads, search]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ITEM_HEIGHT,
  });

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 space-y-4">
        <div className="flex items-center gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
            <Input
              placeholder={t("search")}
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="pl-9"
            />
          </div>
          <Button
            variant="outline"
            size="icon"
            onClick={() => refetch()}
            disabled={isFetching}
          >
            <RefreshCw className={`h-4 w-4 ${isFetching ? "animate-spin" : ""}`} />
          </Button>
        </div>
        <div className="text-xs text-muted-foreground">
          {filtered.length} / {threads.length}
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 min-h-0 h-full overflow-auto">
        {isLoading ? (
          <div className="px-4 space-y-3">
            {Array.from({ length: 8 }).map((_, i) => (
              <div key={i} className="space-y-1.5">
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-3 w-64" />
              </div>
            ))}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((vItem) => {
              const thread = filtered[vItem.index];
              const stateClass = STATE_COLORS[thread.state] ?? "bg-muted text-muted-foreground";
              return (
                <div
                  key={vItem.key}
                  className="absolute left-0 right-0 px-4 py-2.5 border-b border-border hover:bg-accent"
                  style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
                >
                  <div className="flex items-center gap-2 min-w-0">
                    <span className="text-sm font-mono font-medium shrink-0">
                      {thread.id}
                    </span>
                    {thread.name && (
                      <span className="text-sm truncate text-muted-foreground">
                        {thread.name}
                      </span>
                    )}
                    <span
                      className={`ml-auto inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium shrink-0 ${stateClass}`}
                    >
                      {t(`thread_state_${thread.state}`, thread.state)}
                    </span>
                  </div>
                  <div className="text-xs text-muted-foreground font-mono truncate mt-0.5">
                    {thread.symbol
                      ? `${thread.symbol}${thread.moduleName ? ` (${thread.moduleName})` : ""}`
                      : thread.pc}
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}

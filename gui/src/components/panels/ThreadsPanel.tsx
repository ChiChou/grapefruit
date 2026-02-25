import { useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search, RefreshCw } from "lucide-react";
import { List, type RowComponentProps } from "react-window";

import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Skeleton } from "@/components/ui/skeleton";
import { usePlatformQuery } from "@/lib/queries";
import type { ThreadInfo } from "@agent/common/threads";

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
      <div className="flex-1 min-h-0 h-full">
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
          <div className="flex h-full">
            <List
              rowComponent={ThreadRow}
              rowCount={filtered.length}
              rowHeight={ITEM_HEIGHT}
              rowProps={{ threads: filtered }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

function ThreadRow({
  index,
  style,
  threads,
}: RowComponentProps<{
  threads: ThreadInfo[];
}>) {
  const { t } = useTranslation();
  const thread = threads[index];
  const stateClass = STATE_COLORS[thread.state] ?? "bg-muted text-muted-foreground";

  return (
    <div
      className="px-4 py-2.5 border-b border-border hover:bg-accent"
      style={style}
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
}

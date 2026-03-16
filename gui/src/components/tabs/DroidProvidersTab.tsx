import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import { Search, Globe, Play, CircleAlert, Info } from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";

import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { useDroidQuery, useDroidMutation } from "@/lib/queries";

import type { ProviderEntry } from "@agent/droid/modules/provider";
import type { QueryResult, QueryOptions } from "@agent/droid/modules/provider";

const ITEM_HEIGHT = 56;

function shortName(fullName: string): string {
  const idx = fullName.lastIndexOf(".");
  return idx >= 0 ? fullName.substring(idx + 1) : fullName;
}

function QueryError({ error }: { error: Error }) {
  const { t } = useTranslation();

  return (
    <div className="p-4">
      <Alert variant="destructive">
        <CircleAlert className="h-4 w-4" />
        <AlertTitle>{t("error")}</AlertTitle>
        <AlertDescription className="font-mono text-xs mt-2">
          {error.message}
        </AlertDescription>
      </Alert>
    </div>
  );
}

function ResultsTable({ result }: { result: QueryResult }) {
  const { t } = useTranslation();

  if (result.columns.length === 0) {
    return (
      <div className="p-4">
        <Alert>
          <Info className="h-4 w-4" />
          <AlertDescription>{t("query_executed_no_results")}</AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="overflow-auto h-full">
      <table className="w-full text-sm border-collapse">
        <thead className="sticky top-0 bg-background z-10">
          <tr>
            {result.columns.map((col) => (
              <th
                key={col}
                className="text-left px-3 py-2 border-b border-border font-medium text-xs text-muted-foreground whitespace-nowrap"
              >
                {col}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {result.rows.map((row, i) => (
            <tr key={i} className="hover:bg-accent">
              {row.map((cell, j) => (
                <td
                  key={j}
                  className="px-3 py-1.5 border-b border-border/50 font-mono text-xs whitespace-nowrap max-w-xs truncate"
                >
                  {cell === null ? (
                    <span className="text-muted-foreground italic">NULL</span>
                  ) : (
                    String(cell)
                  )}
                </td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="text-xs text-muted-foreground p-2 border-t border-border">
        {t("rows_returned", { count: result.rows.length })}
      </div>
    </div>
  );
}

function QueryPane({ initialUri }: { initialUri: string }) {
  const { t } = useTranslation();
  const [uri, setUri] = useState(initialUri);
  const [projection, setProjection] = useState("");
  const [selection, setSelection] = useState("");
  const [selectionArgs, setSelectionArgs] = useState("");
  const [sortOrder, setSortOrder] = useState("");

  const queryMutation = useDroidMutation<
    QueryResult,
    { uri: string; options?: QueryOptions }
  >((api, { uri, options }) => api.provider.query(uri, options));

  // Sync URI and clear results when provider selection changes
  const [lastInitialUri, setLastInitialUri] = useState(initialUri);
  if (initialUri !== lastInitialUri) {
    setUri(initialUri);
    setLastInitialUri(initialUri);
    queryMutation.reset();
  }

  const handleExecute = () => {
    if (!uri.trim()) return;

    const options: QueryOptions = {};
    if (projection.trim()) {
      options.projection = projection.split(",").map((s) => s.trim());
    }
    if (selection.trim()) {
      options.selection = selection;
    }
    if (selectionArgs.trim()) {
      options.selectionArgs = selectionArgs.split(",").map((s) => s.trim());
    }
    if (sortOrder.trim()) {
      options.sortOrder = sortOrder;
    }

    queryMutation.mutate({
      uri: uri.trim(),
      options: Object.keys(options).length > 0 ? options : undefined,
    });
  };

  return (
    <div className="h-full flex flex-col">
      <div className="p-4 space-y-3 border-b border-border shrink-0">
        <div className="space-y-1.5">
          <Label className="text-xs">Content URI</Label>
          <Input
            placeholder="content://authority/path"
            value={uri}
            onChange={(e) => setUri(e.target.value)}
            className="font-mono text-sm"
            onKeyDown={(e) => {
              if (e.key === "Enter") handleExecute();
            }}
          />
        </div>
        <div className="grid grid-cols-2 gap-3">
          <div className="space-y-1.5">
            <Label className="text-xs">{t("projection")}</Label>
            <Input
              placeholder={t("projection_placeholder")}
              value={projection}
              onChange={(e) => setProjection(e.target.value)}
              className="text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">{t("sort_order")}</Label>
            <Input
              placeholder={t("sort_order_placeholder")}
              value={sortOrder}
              onChange={(e) => setSortOrder(e.target.value)}
              className="text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">{t("selection")}</Label>
            <Input
              placeholder={t("selection_placeholder")}
              value={selection}
              onChange={(e) => setSelection(e.target.value)}
              className="text-xs"
            />
          </div>
          <div className="space-y-1.5">
            <Label className="text-xs">{t("selection_args")}</Label>
            <Input
              placeholder={t("selection_args_placeholder")}
              value={selectionArgs}
              onChange={(e) => setSelectionArgs(e.target.value)}
              className="text-xs"
            />
          </div>
        </div>
        <Button
          size="sm"
          onClick={handleExecute}
          disabled={!uri.trim() || queryMutation.isPending}
        >
          <Play className="h-3.5 w-3.5 mr-1.5" />
          {t("execute")}
        </Button>
      </div>
      <div className="flex-1 min-h-0 overflow-auto">
        {queryMutation.isPending ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner />
            {t("loading")}...
          </div>
        ) : queryMutation.isError ? (
          <QueryError error={queryMutation.error} />
        ) : queryMutation.data ? (
          <ResultsTable result={queryMutation.data} />
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            {t("no_query_results")}
          </div>
        )}
      </div>
    </div>
  );
}

export function DroidProvidersTab() {
  const { t } = useTranslation();
  const [search, setSearch] = useState("");
  const [selectedAuthority, setSelectedAuthority] = useState<string | null>(
    null,
  );
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data: providers = [], isLoading } = useDroidQuery<ProviderEntry[]>(
    ["providers"],
    (api) => api.provider.list(),
  );

  const filtered = useMemo(() => {
    if (!search.trim()) return providers;
    const query = search.toLowerCase();
    return providers.filter(
      (p) =>
        p.name.toLowerCase().includes(query) ||
        p.authority.toLowerCase().includes(query),
    );
  }, [providers, search]);

  const virtualizer = useVirtualizer({
    count: filtered.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ITEM_HEIGHT,
  });

  const handleSelect = (authority: string) => {
    setSelectedAuthority(authority);
  };

  const queryUri = selectedAuthority ? `content://${selectedAuthority}/` : "";

  const listPane = (
    <div className="h-full flex flex-col">
      <div className="p-3 space-y-2 border-b border-border">
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
          {filtered.length} / {providers.length}
        </div>
      </div>
      <div ref={scrollRef} className="flex-1 min-h-0 overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner />
            {t("loading")}...
          </div>
        ) : filtered.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_providers")}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((vItem) => {
              const item = filtered[vItem.index];
              const isSelected = item.authority === selectedAuthority;
              return (
                <button
                  key={vItem.key}
                  type="button"
                  className={`absolute left-0 right-0 w-full text-left px-4 py-2 border-b border-border hover:bg-accent ${isSelected ? "bg-accent" : ""}`}
                  style={{ height: vItem.size, transform: `translateY(${vItem.start}px)` }}
                  onClick={() => handleSelect(item.authority)}
                >
                  <div className="flex items-center justify-between">
                    <div className="min-w-0 flex-1">
                      <div className="text-sm font-medium truncate">
                        {shortName(item.name)}
                      </div>
                      <div className="text-xs text-muted-foreground font-mono truncate">
                        {item.authority}
                      </div>
                    </div>
                    <div className="flex items-center gap-1 shrink-0 ml-2">
                      {item.exported && (
                        <Globe className="h-3.5 w-3.5 text-muted-foreground" />
                      )}
                    </div>
                  </div>
                </button>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="providers-tab-split"
    >
      <ResizablePanel defaultSize="35%" minSize="20%">
        {listPane}
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel>
        <QueryPane initialUri={queryUri} />
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

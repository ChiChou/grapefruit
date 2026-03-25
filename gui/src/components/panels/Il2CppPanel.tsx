import { useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Search,
  FileCode,
  ChevronRight,
  ChevronDown,
  RefreshCw,
} from "lucide-react";
import { SiUnity } from "@icons-pack/react-simple-icons";
import { useVirtualizer } from "@tanstack/react-virtual";

import { Input } from "@/components/ui/input";
import { Skeleton } from "@/components/ui/skeleton";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Spinner } from "@/components/ui/spinner";
import { useDock } from "@/context/DockContext";
import { Platform, useSession } from "@/context/SessionContext";
import { usePlatformQuery, useQueryClient } from "@/lib/queries";

import type {
  Il2CppAssemblyInfo,
  Il2CppRuntimeInfo,
  Il2CppThreadInfo,
} from "@agent/common/il2cpp";

const ITEM_HEIGHT = 32;

interface FlatEntry {
  kind: "assembly" | "class";
  assemblyName: string;
  label: string;
  fullName?: string;
}

function formatBytes(s: string): string {
  const n = Number(s);
  if (Number.isNaN(n) || n === 0) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  const i = Math.min(Math.floor(Math.log2(n) / 10), units.length - 1);
  return `${(n / 2 ** (i * 10)).toFixed(1)} ${units[i]}`;
}

export function Il2CppPanel() {
  const { data: il2cppAvailable, isLoading: checkingAvailable } = usePlatformQuery(
    ["il2cpp", "available"],
    (api) => (api as any).il2cpp.available() as Promise<boolean>,
  );

  if (checkingAvailable) {
    return (
      <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
        <Spinner />
      </div>
    );
  }

  if (il2cppAvailable === false) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-muted-foreground text-sm gap-3 p-6 text-center">
        <SiUnity className="h-10 w-10 opacity-40" />
        <div className="space-y-1">
          <div className="font-medium">IL2CPP not detected</div>
          <div className="text-xs">
            This process does not appear to be a Unity/IL2CPP application.
          </div>
        </div>
      </div>
    );
  }

  return (
    <Tabs defaultValue="assemblies" className="h-full gap-0">
      <div className="px-3 pt-2 pb-0">
        <TabsList variant="line" className="w-full">
          <TabsTrigger value="runtime" className="flex-1">
            Runtime
          </TabsTrigger>
          <TabsTrigger value="assemblies" className="flex-1">
            Assemblies
          </TabsTrigger>
          <TabsTrigger value="threads" className="flex-1">
            Threads
          </TabsTrigger>
        </TabsList>
      </div>

      <TabsContent value="runtime" className="flex-1 min-h-0 overflow-auto">
        <RuntimeTab />
      </TabsContent>
      <TabsContent value="assemblies" className="flex-1 min-h-0 flex flex-col overflow-hidden">
        <AssembliesTab />
      </TabsContent>
      <TabsContent value="threads" className="flex-1 min-h-0 overflow-auto">
        <ThreadsTab />
      </TabsContent>
    </Tabs>
  );
}

// ── Runtime Tab ─────────────────────────────────────────────────────

function RuntimeTab() {
  const queryClient = useQueryClient();

  const { data: info, isLoading } = usePlatformQuery(
    ["il2cpp", "info"],
    (api) => (api as any).il2cpp.info() as Promise<Il2CppRuntimeInfo>,
  );

  if (isLoading) {
    return (
      <div className="p-3 space-y-2">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-5 w-3/4" />
        ))}
      </div>
    );
  }

  if (!info) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
        Unavailable
      </div>
    );
  }

  return (
    <div className="p-3 space-y-4">
      <Section title="Application">
        <InfoRow label="Unity" value={info.unityVersion} />
        <InfoRow label="Module" value={info.moduleName} />
        <InfoRow label="Base" value={info.moduleBase} />
        <InfoRow label="Identifier" value={info.appIdentifier} />
        <InfoRow label="Version" value={info.appVersion} />
        <InfoRow label="Data Path" value={info.appDataPath ?? "N/A"} />
        <InfoRow label="Assemblies" value={String(info.assemblyCount)} />
      </Section>

      <Section
        title="Garbage Collector"
        action={
          <Button
            variant="ghost"
            size="sm"
            className="h-5 text-xs -my-0.5"
            onClick={() =>
              queryClient.invalidateQueries({ queryKey: ["il2cpp", "info"] })
            }
          >
            <RefreshCw className="h-3 w-3" />
          </Button>
        }
      >
        <InfoRow label="Heap" value={formatBytes(info.gc.heapSize)} />
        <InfoRow label="Used" value={formatBytes(info.gc.usedHeapSize)} />
        <InfoRow label="Enabled" value={info.gc.isEnabled ? "Yes" : "No"} />
        <InfoRow label="Incremental" value={info.gc.isIncremental ? "Yes" : "No"} />
      </Section>
    </div>
  );
}

// ── Assemblies Tab ──────────────────────────────────────────────────

function AssembliesTab() {
  const { t } = useTranslation();
  const { openFilePanel } = useDock();
  const { platform, fruity, droid } = useSession();
  const rpcApi = platform === Platform.Droid ? droid : fruity;
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());
  const [classCache, setClassCache] = useState<Record<string, string[]>>({});
  const [loadingAssemblies, setLoadingAssemblies] = useState<Set<string>>(new Set());
  const scrollRef = useRef<HTMLDivElement>(null);

  const { data: assemblies = [], isLoading } = usePlatformQuery(
    ["il2cpp", "assemblies"],
    (api) => (api as any).il2cpp.assemblies() as Promise<Il2CppAssemblyInfo[]>,
  );

  const toggleAssembly = async (name: string) => {
    if (expanded.has(name)) {
      setExpanded((prev) => {
        const next = new Set(prev);
        next.delete(name);
        return next;
      });
      return;
    }
    setExpanded((prev) => new Set(prev).add(name));
    if (!classCache[name] && rpcApi) {
      setLoadingAssemblies((prev) => new Set(prev).add(name));
      try {
        const classes = (await (rpcApi as any).il2cpp.classes(name)) as string[];
        setClassCache((prev) => ({ ...prev, [name]: classes }));
      } catch {
        // skip
      } finally {
        setLoadingAssemblies((prev) => {
          const next = new Set(prev);
          next.delete(name);
          return next;
        });
      }
    }
  };

  const flatList = useMemo((): FlatEntry[] => {
    const query = search.toLowerCase();
    const entries: FlatEntry[] = [];
    if (search.trim()) {
      for (const asm of assemblies) {
        const classes = classCache[asm.name] ?? [];
        for (const cls of classes) {
          if (cls.toLowerCase().includes(query)) {
            entries.push({ kind: "class", assemblyName: asm.name, label: cls, fullName: cls });
          }
        }
      }
      return entries;
    }
    for (const asm of assemblies) {
      entries.push({ kind: "assembly", assemblyName: asm.name, label: `${asm.name} (${asm.classCount})` });
      if (expanded.has(asm.name)) {
        for (const cls of classCache[asm.name] ?? []) {
          entries.push({ kind: "class", assemblyName: asm.name, label: cls, fullName: cls });
        }
      }
    }
    return entries;
  }, [assemblies, expanded, classCache, search]);

  const virtualizer = useVirtualizer({
    count: flatList.length,
    getScrollElement: () => scrollRef.current,
    estimateSize: () => ITEM_HEIGHT,
  });

  return (
    <>
      <div className="p-4 space-y-3 shrink-0">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <Input
            placeholder={t("search")}
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="pl-9"
          />
        </div>
        {!isLoading && (
          <div className="text-xs text-muted-foreground">
            {search.trim()
              ? `${flatList.length.toLocaleString()} results`
              : `${assemblies.length} assemblies`}
          </div>
        )}
      </div>

      <div ref={scrollRef} className="flex-1 min-h-0 overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner />
          </div>
        ) : flatList.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
            {t("no_results")}
          </div>
        ) : (
          <div style={{ height: virtualizer.getTotalSize(), position: "relative" }}>
            {virtualizer.getVirtualItems().map((vItem) => {
              const entry = flatList[vItem.index];
              const style = { height: vItem.size, transform: `translateY(${vItem.start}px)` };
              if (entry.kind === "assembly") {
                return (
                  <AssemblyRow
                    key={vItem.key}
                    entry={entry}
                    isExpanded={expanded.has(entry.assemblyName)}
                    isLoading={loadingAssemblies.has(entry.assemblyName)}
                    style={style}
                    onToggle={() => toggleAssembly(entry.assemblyName)}
                  />
                );
              }
              return (
                <ClassRow
                  key={vItem.key}
                  entry={entry}
                  inSearch={!!search.trim()}
                  style={style}
                  onClickClass={() =>
                    openFilePanel({
                      id: `il2cpp_class_${entry.assemblyName}_${entry.fullName}`,
                      component: "il2cppClassDetail",
                      title: entry.fullName ?? entry.label,
                      params: { assemblyName: entry.assemblyName, fullName: entry.fullName! },
                    })
                  }
                  onClickDump={() =>
                    openFilePanel({
                      id: `il2cpp_dump_${entry.assemblyName}_${entry.fullName}`,
                      component: "il2cppClassDump",
                      title: `Dump: ${entry.fullName}`,
                      params: { assemblyName: entry.assemblyName, fullName: entry.fullName! },
                    })
                  }
                />
              );
            })}
          </div>
        )}
      </div>
    </>
  );
}

// ── Threads Tab ─────────────────────────────────────────────────────

function ThreadsTab() {
  const queryClient = useQueryClient();

  const { data: threads = [], isLoading } = usePlatformQuery(
    ["il2cpp", "threads"],
    (api) => (api as any).il2cpp.threads() as Promise<Il2CppThreadInfo[]>,
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
        <Spinner />
      </div>
    );
  }

  return (
    <div>
      <div className="flex items-center px-4 py-2">
        <span className="text-xs text-muted-foreground flex-1">
          {threads.length} managed thread{threads.length !== 1 ? "s" : ""}
        </span>
        <Button
          variant="ghost"
          size="sm"
          className="h-5 text-xs"
          onClick={() =>
            queryClient.invalidateQueries({ queryKey: ["il2cpp", "threads"] })
          }
        >
          <RefreshCw className="h-3 w-3" />
        </Button>
      </div>
      {threads.length === 0 ? (
        <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
          No managed threads
        </div>
      ) : (
        <table className="w-full text-xs">
          <thead>
            <tr className="bg-muted/50">
              <th className="px-4 py-1.5 text-left font-medium">ID</th>
              <th className="px-4 py-1.5 text-left font-medium">Managed</th>
              <th className="px-4 py-1.5 text-left font-medium">Type</th>
            </tr>
          </thead>
          <tbody>
            {threads.map((t) => (
              <tr key={t.id} className="border-t border-border hover:bg-accent/30">
                <td className="px-4 py-1.5 font-mono">{t.id}</td>
                <td className="px-4 py-1.5 font-mono">{t.managedId}</td>
                <td className="px-4 py-1.5">{t.isFinalizer ? "Finalizer" : "User"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}

// ── Shared sub-components ───────────────────────────────────────────

function Section({
  title,
  action,
  children,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
}) {
  return (
    <div className="space-y-1.5">
      <div className="flex items-center gap-2">
        <h3 className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
          {title}
        </h3>
        {action}
      </div>
      <div className="space-y-0.5">{children}</div>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 py-0.5">
      <span className="text-xs text-muted-foreground w-24 shrink-0">{label}</span>
      <span className="text-xs font-mono truncate">{value}</span>
    </div>
  );
}

function AssemblyRow({
  entry,
  isExpanded,
  isLoading,
  style,
  onToggle,
}: {
  entry: FlatEntry;
  isExpanded: boolean;
  isLoading: boolean;
  style: React.CSSProperties;
  onToggle: () => void;
}) {
  return (
    <div
      className="absolute left-0 right-0 px-4 py-1.5 border-b border-border hover:bg-accent transition-colors flex items-center cursor-pointer"
      style={style}
      onClick={onToggle}
    >
      {isExpanded ? (
        <ChevronDown className="h-3.5 w-3.5 shrink-0 mr-1 text-muted-foreground" />
      ) : (
        <ChevronRight className="h-3.5 w-3.5 shrink-0 mr-1 text-muted-foreground" />
      )}
      <span className="text-sm font-medium truncate">{entry.label}</span>
      {isLoading && (
        <span className="ml-2 text-xs text-muted-foreground animate-pulse">loading...</span>
      )}
    </div>
  );
}

function ClassRow({
  entry,
  inSearch,
  style,
  onClickClass,
  onClickDump,
}: {
  entry: FlatEntry;
  inSearch: boolean;
  style: React.CSSProperties;
  onClickClass: () => void;
  onClickDump: () => void;
}) {
  return (
    <div
      className="absolute left-0 right-0 border-b border-border hover:bg-accent transition-colors group flex items-center"
      style={{
        ...style,
        paddingLeft: inSearch ? "1rem" : "1.75rem",
        paddingRight: "1rem",
        paddingTop: "0.375rem",
        paddingBottom: "0.375rem",
      }}
    >
      <button
        type="button"
        className="text-sm font-mono truncate text-foreground/80 hover:text-primary transition-colors flex-1 text-left cursor-pointer"
        onClick={onClickClass}
      >
        {inSearch && (
          <span className="text-muted-foreground text-xs mr-1">{entry.assemblyName}/</span>
        )}
        {entry.fullName}
      </button>
      <Button
        variant="ghost"
        size="icon"
        className="h-6 w-6 shrink-0 text-muted-foreground opacity-0 group-hover:opacity-100"
        title="Dump C#"
        onClick={onClickDump}
      >
        <FileCode className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

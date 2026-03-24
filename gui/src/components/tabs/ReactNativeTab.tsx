import { useState, useCallback, useEffect } from "react";
import { Download, FileSearch, RefreshCw, Trash2, X } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Spinner } from "../ui/spinner";
import { usePlatformQuery } from "@/lib/queries";
import { useQuery } from "@tanstack/react-query";
import { Platform, Status, useSession } from "@/context/SessionContext";
import ConsoleRepl from "@/components/shared/ConsoleRepl";
import { useDock } from "@/context/DockContext";
import { t } from "i18next";

interface RNInstance {
  className: string;
  arch: "legacy" | "bridgeless";
  handle: string;
}

interface HermesEntry {
  id: number;
  url: string;
  hash: string;
  size: number;
  createdAt: string | null;
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function filenameFromUrl(url: string): string {
  const parts = url.split("/");
  return parts[parts.length - 1] || url;
}

export function ReactNativeTab() {
  const [selected, setSelected] = useState<RNInstance | null>(null);
  const { fruity, droid, platform, socket, status, device, identifier } =
    useSession();
  const { openFilePanel } = useDock();

  const { data: archResult, isLoading: archLoading } = usePlatformQuery<{
    legacy: boolean;
    bridgeless: boolean;
  }>(["rnArch"], (api) => api.rn.arch());

  const detected = archResult?.legacy || archResult?.bridgeless;

  const {
    data: instances = [],
    isLoading: instancesLoading,
    refetch,
  } = usePlatformQuery<RNInstance[]>(["rnList"], (api) => api.rn.list(), {
    enabled: !!detected,
  });

  // Hermes bundles from REST
  const {
    data: hermesData,
    isLoading: hermesLoading,
    refetch: refetchHermes,
  } = useQuery<{ logs: HermesEntry[]; total: number }>({
    queryKey: ["hermesHistory", device, identifier],
    queryFn: async () => {
      const res = await fetch(`/api/hermes/${device}/${identifier}?limit=1000`);
      if (!res.ok) throw new Error("Failed to load Hermes bundles");
      return res.json();
    },
    enabled: !!device && !!identifier,
    staleTime: 0,
    gcTime: 0,
  });

  const hermesBundles = hermesData?.logs ?? [];

  // Reload list on websocket hermes event
  useEffect(() => {
    if (status !== Status.Ready || !socket) return;
    const onHermes = () => {
      refetchHermes();
    };
    socket.on("hermes", onHermes);
    return () => {
      socket.off("hermes", onHermes);
    };
  }, [socket, status, refetchHermes]);

  const handleDownload = async (entry: HermesEntry) => {
    const res = await fetch(
      `/api/hermes/${device}/${identifier}/download/${entry.id}`,
    );
    if (!res.ok) return;
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filenameFromUrl(entry.url);
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleDeleteBundle = async (entry: HermesEntry) => {
    const res = await fetch(
      `/api/hermes/${device}/${identifier}/${entry.id}`,
      { method: "DELETE" },
    );
    if (res.ok) refetchHermes();
  };

  const handleClearBundles = async () => {
    const res = await fetch(`/api/hermes/${device}/${identifier}`, {
      method: "DELETE",
    });
    if (res.ok) refetchHermes();
  };

  const api = platform === Platform.Droid ? droid : fruity;

  const handleEvaluate = useCallback(
    async (input: string) => {
      if (!selected || !api) throw new Error("No instance selected");
      const raw = await api.rn.inject(selected.handle, selected.arch, input);
      if (raw === "undefined" || raw === undefined) return undefined;
      const parsed = JSON.parse(raw);
      if (
        parsed !== null &&
        typeof parsed === "object" &&
        "error" in parsed &&
        typeof parsed.error === "string"
      ) {
        throw new Error(parsed.error);
      }
      return parsed;
    },
    [selected, api],
  );

  if (archLoading) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground">
        <Spinner className="mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (!detected) {
    return (
      <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
        {t("rn_not_detected")}
      </div>
    );
  }

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      autoSaveId="rn-instances"
      className="h-full"
    >
      <ResizablePanel defaultSize={30} minSize={20}>
        <div className="h-full flex flex-col border-r">
          <ResizablePanelGroup
            orientation="vertical"
            autoSaveId="rn-left-panel"
          >
            {/* Top: Instances */}
            <ResizablePanel defaultSize={50} minSize={20}>
              <div className="h-full flex flex-col">
                <div className="flex items-center justify-between px-3 py-2 border-b gap-2">
                  <div className="flex items-center gap-1.5">
                    <h2 className="text-sm font-semibold">
                      {t("rn_instances")}
                    </h2>
                    {archResult?.legacy && (
                      <Badge className="text-[10px] px-1.5 py-0">legacy</Badge>
                    )}
                    {archResult?.bridgeless && (
                      <Badge className="text-[10px] px-1.5 py-0">
                        bridgeless
                      </Badge>
                    )}
                  </div>
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-7 w-7"
                    onClick={() => refetch()}
                    disabled={instancesLoading}
                  >
                    <RefreshCw
                      className={`h-3.5 w-3.5 ${instancesLoading ? "animate-spin" : ""}`}
                    />
                  </Button>
                </div>
                <ScrollArea className="flex-1">
                  {instancesLoading ? (
                    <div className="flex items-center justify-center py-8 text-muted-foreground">
                      <Spinner className="mr-2" />
                      <span className="text-sm">{t("loading")}</span>
                    </div>
                  ) : instances.length === 0 ? (
                    <div className="px-3 py-4 text-xs text-muted-foreground text-center">
                      {t("rn_no_instances")}
                    </div>
                  ) : (
                    instances.map((inst) => (
                      <button
                        key={inst.handle}
                        className={`w-full text-left px-3 py-2 text-sm border-b hover:bg-accent transition-colors ${
                          selected?.handle === inst.handle ? "bg-accent" : ""
                        }`}
                        onClick={() => setSelected(inst)}
                      >
                        <div className="flex items-center gap-2 min-w-0">
                          <Badge className="text-[10px] px-1.5 py-0 shrink-0">
                            {inst.arch}
                          </Badge>
                          <span className="text-xs truncate">
                            {inst.className}
                          </span>
                          <span className="font-mono text-xs text-muted-foreground truncate shrink-0">
                            {inst.handle}
                          </span>
                        </div>
                      </button>
                    ))
                  )}
                </ScrollArea>
              </div>
            </ResizablePanel>

            <ResizableHandle />

            {/* Bottom: Hermes Bundles */}
            <ResizablePanel defaultSize={50} minSize={20}>
              <div className="h-full flex flex-col">
                <div className="flex items-center justify-between px-3 py-2 border-b gap-2">
                  <div className="flex items-center gap-1.5">
                    <h2 className="text-sm font-semibold">
                      {t("rn_js_bundles")}
                    </h2>
                    <Badge
                      variant="secondary"
                      className="text-[10px] px-1.5 py-0"
                    >
                      {hermesBundles.length}
                    </Badge>
                  </div>
                  <div className="flex items-center gap-0.5">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => refetchHermes()}
                      disabled={hermesLoading}
                    >
                      <RefreshCw
                        className={`h-3.5 w-3.5 ${hermesLoading ? "animate-spin" : ""}`}
                      />
                    </Button>
                    <DropdownMenu>
                      <DropdownMenuTrigger
                        render={
                          <Button
                            variant="ghost"
                            size="icon"
                            className="h-7 w-7"
                            disabled={hermesBundles.length === 0}
                          />
                        }
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          onClick={handleClearBundles}
                          className="text-destructive focus:text-destructive"
                        >
                          {t("clear_all")}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </div>
                </div>
                <ScrollArea className="flex-1">
                  {hermesLoading ? (
                    <div className="flex items-center justify-center py-8 text-muted-foreground">
                      <Spinner className="mr-2" />
                      <span className="text-sm">{t("loading")}</span>
                    </div>
                  ) : hermesBundles.length === 0 ? (
                    <div className="px-3 py-4 text-xs text-muted-foreground text-center">
                      {t("rn_no_bundles")}
                    </div>
                  ) : (
                    hermesBundles.map((entry) => (
                      <div
                        key={entry.id}
                        className="flex items-center gap-2 px-3 py-1.5 border-b hover:bg-accent/50 min-w-0"
                      >
                        <div className="flex-1 min-w-0">
                          <div
                            className="font-mono text-xs truncate"
                            title={entry.url}
                          >
                            {filenameFromUrl(entry.url)}
                          </div>
                          <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                            <span className="font-mono">
                              {entry.hash.slice(0, 12)}
                            </span>
                            <span>{formatSize(entry.size)}</span>
                          </div>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 shrink-0"
                          onClick={() =>
                            openFilePanel({
                              id: `hermes_analysis_${entry.id}`,
                              component: "hermesAnalysis",
                              title: `HBC: ${filenameFromUrl(entry.url).slice(0, 30)}`,
                              params: {
                                entryId: entry.id,
                                filename: filenameFromUrl(entry.url),
                              },
                            })
                          }
                          title="Analyze"
                        >
                          <FileSearch className="h-3 w-3" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-6 w-6 shrink-0"
                          onClick={() => handleDownload(entry)}
                          title={t("download")}
                        >
                          <Download className="h-3 w-3" />
                        </Button>
                        <DropdownMenu>
                          <DropdownMenuTrigger
                            render={
                              <Button
                                variant="ghost"
                                size="icon"
                                className="h-6 w-6 shrink-0"
                              />
                            }
                          >
                            <X className="h-3 w-3" />
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem
                              onClick={() => handleDeleteBundle(entry)}
                              className="text-destructive focus:text-destructive"
                            >
                              {t("delete")}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    ))
                  )}
                </ScrollArea>
              </div>
            </ResizablePanel>
          </ResizablePanelGroup>
        </div>
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel defaultSize={70} minSize={30}>
        {selected ? (
          <ConsoleRepl
            key={selected.handle}
            onEvaluate={handleEvaluate}
            placeholder={t("rn_js_expression")}
          />
        ) : (
          <div className="h-full flex items-center justify-center text-sm text-muted-foreground">
            {t("rn_select_instance")}
          </div>
        )}
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

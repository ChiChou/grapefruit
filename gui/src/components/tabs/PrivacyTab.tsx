import { useEffect, useMemo, useRef, useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { type ColumnDef } from "@tanstack/react-table";

import {
  Trash2,
  Play,
  Square,
  Loader2,
  ChevronsDown,
  Mic,
  Camera,
  MapPin,
  Heart,
  Image,
  Activity,
  Bluetooth,
  Wifi,
  Eye,
  Gamepad2,
  Home,
  ShieldAlert,
  Radar,
  Footprints,
  BarChart3,
} from "lucide-react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  ResizableHandle,
  ResizablePanel,
  ResizablePanelGroup,
} from "@/components/ui/resizable";
import { LogTable } from "@/components/shared/LogTable";
import { Status, Platform, useSession } from "@/context/SessionContext";
import { useLogStream } from "@/hooks/useLogStream";
import { toTime } from "@/lib/format";

import type {
  PrivacyMessage as DroidPrivacyMessage,
  PrivacySeverity as DroidPrivacySeverity,
  PrivacyCategory as DroidPrivacyCategory,
} from "@agent/droid/hooks/privacy/types";
import type {
  PrivacyMessage as FruityPrivacyMessage,
  PrivacySeverity as FruityPrivacySeverity,
  PrivacyCategory as FruityPrivacyCategory,
} from "@agent/fruity/hooks/privacy/types";

type PrivacyMessage = DroidPrivacyMessage | FruityPrivacyMessage;
type PrivacySeverity = DroidPrivacySeverity | FruityPrivacySeverity;
type PrivacyCategory = DroidPrivacyCategory | FruityPrivacyCategory;

const TAP_ID = "privacy";

const SEVERITY_CONFIG: Record<
  PrivacySeverity,
  { label: string; badge: string; border: string }
> = {
  critical: {
    label: "Critical",
    badge: "bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400",
    border: "border-l-red-500",
  },
  medium: {
    label: "Medium",
    badge:
      "bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400",
    border: "border-l-amber-500",
  },
  low: {
    label: "Low",
    badge:
      "bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400",
    border: "border-l-green-500",
  },
  informative: {
    label: "Info",
    badge: "bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-400",
    border: "border-l-blue-500",
  },
};

const CATEGORY_ICONS: Record<PrivacyCategory, typeof Mic> = {
  microphone: Mic,
  camera: Camera,
  location: MapPin,
  health: Heart,
  photos: Image,
  motion_sensors: Activity,
  bluetooth: Bluetooth,
  wifi: Wifi,
  focus_status: Eye,
  game_center: Gamepad2,
  homekit: Home,
  safetykit: ShieldAlert,
  sensorkit: Radar,
  activity_recognition: Footprints,
  usage_stats: BarChart3,
};

const CATEGORY_LABELS: Record<PrivacyCategory, string> = {
  microphone: "Microphone",
  camera: "Camera",
  location: "Location",
  health: "Health",
  photos: "Photos",
  motion_sensors: "Sensors",
  bluetooth: "Bluetooth",
  wifi: "Wi-Fi",
  focus_status: "Focus",
  game_center: "Game Center",
  homekit: "HomeKit",
  safetykit: "SafetyKit",
  sensorkit: "SensorKit",
  activity_recognition: "Activity",
  usage_stats: "Usage Stats",
};

interface PrivacyEntry {
  id: number;
  timestamp: Date;
  severity: PrivacySeverity;
  category: PrivacyCategory;
  symbol: string;
  direction: string;
  line?: string;
  backtrace?: string[];
  extra?: Record<string, unknown>;
}

const mapHistory = (
  record: Record<string, unknown>,
  id: number,
): PrivacyEntry => ({
  id,
  timestamp: new Date(record.timestamp as string),
  severity: (record.severity as PrivacySeverity) ?? "informative",
  category: (record.category as PrivacyCategory) ?? "microphone",
  symbol: (record.symbol as string) ?? "",
  direction: (record.direction as string) ?? "enter",
  line: record.line as string | undefined,
  backtrace: record.backtrace as string[] | undefined,
  extra: record.extra as Record<string, unknown> | undefined,
});

const mapSocket = (id: number, ...args: unknown[]): PrivacyEntry => {
  const raw = args[0] as PrivacyMessage;
  return {
    id,
    timestamp: new Date(),
    severity: raw.severity,
    category: raw.category,
    symbol: raw.symbol,
    direction: raw.dir,
    line: raw.line,
    backtrace: raw.backtrace,
    extra: raw.extra,
  };
};

const columns: ColumnDef<PrivacyEntry>[] = [
  {
    id: "timestamp",
    header: "Time",
    size: 96,
    cell: ({ row }) => (
      <span className="font-mono text-muted-foreground">
        {toTime(row.original.timestamp)}
      </span>
    ),
  },
  {
    id: "severity",
    header: "Severity",
    size: 80,
    cell: ({ row }) => {
      const cfg = SEVERITY_CONFIG[row.original.severity];
      return (
        <span
          className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${cfg.badge}`}
        >
          {cfg.label}
        </span>
      );
    },
  },
  {
    id: "category",
    header: "Category",
    size: 120,
    cell: ({ row }) => {
      const Icon = CATEGORY_ICONS[row.original.category] ?? Activity;
      return (
        <div className="flex items-center gap-1.5">
          <Icon className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
          <span className="truncate">
            {CATEGORY_LABELS[row.original.category] ?? row.original.category}
          </span>
        </div>
      );
    },
  },
  {
    id: "symbol",
    header: "Symbol",
    size: 240,
    cell: ({ row }) => (
      <span
        className="font-mono text-primary truncate"
        title={row.original.symbol}
      >
        {row.original.symbol}
      </span>
    ),
  },
  {
    id: "line",
    header: "Summary",
    size: 280,
    cell: ({ row }) => (
      <span
        className="font-mono text-muted-foreground truncate"
        title={row.original.line}
      >
        {row.original.line || "--"}
      </span>
    ),
  },
];

const ALL_SEVERITIES: PrivacySeverity[] = [
  "critical",
  "medium",
  "low",
  "informative",
];

export function PrivacyTab() {
  const { platform, status, device, identifier, fruity, droid } = useSession();

  const [isActive, setIsActive] = useState<boolean | null>(null);
  const [searchFilter, setSearchFilter] = useState("");
  const [enabledSeverities, setEnabledSeverities] = useState<
    Set<PrivacySeverity>
  >(new Set(ALL_SEVERITIES));
  const tableContainerRef = useRef<HTMLDivElement>(null);

  const agent = platform === Platform.Fruity ? fruity : droid;

  const { entries, selectedId, setSelectedId, clear, clearMutation } =
    useLogStream<PrivacyEntry>({
      event: "privacy",
      path: "history/privacy",
      key: "logs",
      fromRecord: mapHistory,
      fromEvent: mapSocket,
    });

  // Sync initial active state
  const { data: initialActive } = useQuery({
    queryKey: ["privacyActive", platform, device],
    queryFn: () => agent!.pins.active(TAP_ID),
    enabled: status === Status.Ready && !!agent,
  });

  useEffect(() => {
    if (initialActive !== undefined && isActive === null)
      setIsActive(initialActive);
  }, [initialActive, isActive]);

  useEffect(() => {
    setIsActive(false);
  }, [platform, device, identifier]);

  const toggleMutation = useMutation({
    mutationFn: async (enable: boolean) => {
      if (!agent) return;
      if (enable) {
        await agent.pins.start(TAP_ID);
      } else {
        await agent.pins.stop(TAP_ID);
      }
    },
    onSuccess: (_, enable) => {
      setIsActive(enable);
    },
  });

  const toggleSeverity = (s: PrivacySeverity) => {
    setEnabledSeverities((prev) => {
      const next = new Set(prev);
      if (next.has(s)) {
        next.delete(s);
      } else {
        next.add(s);
      }
      return next;
    });
  };

  // Filtered entries
  const filteredEntries = useMemo(() => {
    const q = searchFilter.trim().toLowerCase();
    return entries.filter((e) => {
      if (!enabledSeverities.has(e.severity)) return false;
      if (!q) return true;
      return (
        e.symbol.toLowerCase().includes(q) ||
        (e.line?.toLowerCase().includes(q) ?? false) ||
        e.category.toLowerCase().includes(q)
      );
    });
  }, [entries, searchFilter, enabledSeverities]);

  const selectedEntry = useMemo(
    () => filteredEntries.find((e) => e.id === selectedId) ?? null,
    [filteredEntries, selectedId],
  );

  // Severity counts
  const counts = useMemo(() => {
    const c: Record<PrivacySeverity, number> = {
      critical: 0,
      medium: 0,
      low: 0,
      informative: 0,
    };
    for (const e of entries) c[e.severity]++;
    return c;
  }, [entries]);

  const notReady = status !== Status.Ready;

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      className="h-full"
      autoSaveId="privacy-split"
    >
      <ResizablePanel defaultSize="65%" minSize="30%">
        <div className="h-full flex flex-col overflow-hidden">
          {/* Toolbar */}
          <div className="flex items-center gap-2 p-2 border-b shrink-0 flex-wrap">
            {isActive ? (
              <Button
                variant="outline"
                size="sm"
                className="h-8 px-2.5 text-xs text-red-500 hover:text-red-600"
                onClick={() => toggleMutation.mutate(false)}
                disabled={notReady || toggleMutation.isPending || !agent}
              >
                {toggleMutation.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Square className="w-3.5 h-3.5" />
                )}
                Stop
              </Button>
            ) : (
              <Button
                variant="outline"
                size="sm"
                className="h-8 px-2.5 text-xs text-green-600 hover:text-green-700"
                onClick={() => toggleMutation.mutate(true)}
                disabled={notReady || toggleMutation.isPending || !agent}
              >
                {toggleMutation.isPending ? (
                  <Loader2 className="w-3.5 h-3.5 animate-spin" />
                ) : (
                  <Play className="w-3.5 h-3.5" />
                )}
                Start
              </Button>
            )}

            {/* Severity filters */}
            {ALL_SEVERITIES.map((s) => {
              const cfg = SEVERITY_CONFIG[s];
              const active = enabledSeverities.has(s);
              return (
                <button
                  key={s}
                  type="button"
                  className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[10px] font-medium border transition-opacity ${cfg.badge} ${
                    active ? "opacity-100" : "opacity-30"
                  }`}
                  onClick={() => toggleSeverity(s)}
                >
                  {cfg.label}
                  <span className="font-mono">{counts[s]}</span>
                </button>
              );
            })}

            <Input
              value={searchFilter}
              onChange={(e) => setSearchFilter(e.target.value)}
              placeholder="Filter..."
              className="h-8 max-w-xs"
            />
            <span className="text-xs text-muted-foreground ml-auto">
              {filteredEntries.length} event
              {filteredEntries.length !== 1 ? "s" : ""}
            </span>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8"
              onClick={() =>
                tableContainerRef.current?.scrollTo({
                  top: tableContainerRef.current.scrollHeight,
                  behavior: "smooth",
                })
              }
            >
              <ChevronsDown className="w-4 h-4" />
            </Button>
            <Button
              variant="ghost"
              size="icon"
              className="h-8 w-8 text-red-500 hover:text-red-600 hover:bg-red-100 dark:hover:bg-red-950/30"
              onClick={clear}
              disabled={clearMutation.isPending || entries.length === 0}
            >
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>

          {/* Virtualized table */}
          <LogTable
            data={filteredEntries}
            columns={columns}
            selectedId={selectedId}
            onSelect={setSelectedId}
            scrollRef={tableContainerRef}
          />
        </div>
      </ResizablePanel>

      {selectedEntry && (
        <>
          <ResizableHandle />
          <ResizablePanel defaultSize="35%" minSize="15%">
            <div className="h-full overflow-auto p-3 text-xs">
              <div className="space-y-3">
                <div className="space-y-1">
                  <div>
                    <span className="text-muted-foreground">Time: </span>
                    {toTime(selectedEntry.timestamp)}
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">Severity: </span>
                    <span
                      className={`inline-flex items-center rounded-full px-2 py-0.5 text-[10px] font-medium ${SEVERITY_CONFIG[selectedEntry.severity].badge}`}
                    >
                      {SEVERITY_CONFIG[selectedEntry.severity].label}
                    </span>
                  </div>
                  <div className="flex items-center gap-1.5">
                    <span className="text-muted-foreground">Category: </span>
                    {(() => {
                      const Icon =
                        CATEGORY_ICONS[selectedEntry.category] ?? Activity;
                      return (
                        <Icon className="h-3.5 w-3.5 text-muted-foreground" />
                      );
                    })()}
                    {CATEGORY_LABELS[selectedEntry.category] ??
                      selectedEntry.category}
                  </div>
                  <div>
                    <span className="text-muted-foreground">Symbol: </span>
                    <span className="font-mono text-primary">
                      {selectedEntry.symbol}
                    </span>
                  </div>
                  {selectedEntry.line && (
                    <div>
                      <span className="text-muted-foreground">Summary: </span>
                      <span className="font-mono">{selectedEntry.line}</span>
                    </div>
                  )}
                  <div>
                    <span className="text-muted-foreground">Direction: </span>
                    {selectedEntry.direction}
                  </div>
                </div>

                {selectedEntry.extra &&
                  Object.keys(selectedEntry.extra).length > 0 && (
                    <div>
                      <div className="text-muted-foreground mb-1">Extra</div>
                      <pre className="rounded border bg-muted/20 p-2 overflow-auto max-h-40 whitespace-pre-wrap break-all">
                        {JSON.stringify(selectedEntry.extra, null, 2)}
                      </pre>
                    </div>
                  )}

                {selectedEntry.backtrace &&
                  selectedEntry.backtrace.length > 0 && (
                    <div>
                      <div className="text-muted-foreground mb-1">
                        Backtrace
                      </div>
                      <div className="rounded border bg-muted/20 p-2 overflow-auto max-h-60 text-[10px] font-mono space-y-0.5">
                        {selectedEntry.backtrace.map((frame, i) => (
                          <div
                            key={i}
                            className="p-1 rounded hover:bg-muted/50 break-all"
                          >
                            <span className="text-muted-foreground mr-2">
                              #{i}
                            </span>
                            {frame}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
              </div>
            </div>
          </ResizablePanel>
        </>
      )}
    </ResizablePanelGroup>
  );
}

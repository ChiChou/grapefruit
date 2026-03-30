import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, AlertCircle } from "lucide-react";
import { useR2Session } from "@/lib/use-r2-session";

interface MapEntry {
  name: string;
  vaddr: number;
  size: number;
  perm: string;
}

function permColor(perm: string): string {
  const hasR = perm.includes("r");
  const hasW = perm.includes("w");
  const hasX = perm.includes("x");
  if (hasR && hasW && hasX) return "var(--r2-perm-rwx, rgba(168,85,247,0.7))";
  if (hasR && hasX) return "var(--r2-perm-rx, rgba(249,115,22,0.7))";
  if (hasR && hasW) return "var(--r2-perm-rw, rgba(16,185,129,0.7))";
  if (hasX) return "var(--r2-perm-x)";
  if (hasW) return "var(--r2-perm-w)";
  if (hasR) return "var(--r2-perm-r)";
  return "rgba(128,128,128,0.3)";
}

function permBadges(perm: string) {
  const colors: Record<string, string> = {
    r: "text-green-400",
    w: "text-yellow-400",
    x: "text-red-400",
  };
  return (
    <span className="font-mono text-xs">
      {["r", "w", "x"].map((p) => (
        <span key={p} className={perm.includes(p) ? colors[p] : "text-muted-foreground/30"}>
          {p}
        </span>
      ))}
    </span>
  );
}

function fmt(n: number) {
  if (n >= 1024 * 1024) return `${(n / (1024 * 1024)).toFixed(1)}M`;
  if (n >= 1024) return `${(n / 1024).toFixed(1)}K`;
  return `${n}B`;
}

export function MemoryMapsTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { cmd, isReady, error: sessionError } = useR2Session();
  const [maps, setMaps] = useState<MapEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!isReady) return;
    setLoading(true);
    setError(null);
    try {
      const raw = await cmd("iSj");
      const arr = JSON.parse(raw);
      const entries: MapEntry[] = (Array.isArray(arr) ? arr : [])
        .filter((s: any) => s.size > 0)
        .map((s: any) => ({
          name: s.name ?? "",
          vaddr: s.vaddr ?? 0,
          size: s.size ?? 0,
          perm: s.perm ?? "",
        }));
      setMaps(entries);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [cmd, isReady]);

  useEffect(() => { load(); }, [load]);

  if (sessionError) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-2 text-center">
          <AlertCircle className="h-6 w-6 text-destructive" />
          <p className="text-xs font-mono">{sessionError}</p>
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_loading_sections")}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-2 text-center">
          <AlertCircle className="h-6 w-6 text-destructive" />
          <p className="text-xs font-mono">{error}</p>
        </div>
      </div>
    );
  }

  const total = maps.reduce((a, m) => a + m.size, 0) || 1;

  return (
    <div className="h-full flex flex-col overflow-auto">
      <div className="p-3 border-b">
        <div className="text-xs text-muted-foreground mb-2 uppercase tracking-wider font-semibold">
          {t("r2_section_map")} ({maps.length} sections, {fmt(total)} total)
        </div>
        <div className="flex h-6 rounded overflow-hidden gap-px">
          {maps.map((m, i) => {
            const pct = Math.max((m.size / total) * 100, 0.5);
            return (
              <div
                key={i}
                className="relative group"
                style={{ width: `${pct}%`, backgroundColor: permColor(m.perm) }}
                title={`${m.name} (${fmt(m.size)})`}
              >
                <div className="absolute bottom-full mb-1 left-1/2 -translate-x-1/2 hidden group-hover:block bg-popover text-popover-foreground border rounded px-2 py-1 text-[10px] font-mono whitespace-nowrap z-10 shadow-md">
                  {m.name} · {fmt(m.size)} · 0x{m.vaddr.toString(16)}
                </div>
              </div>
            );
          })}
        </div>
        <div className="flex gap-4 mt-2 text-[10px] text-muted-foreground">
          <span><span className="inline-block w-2 h-2 rounded-sm mr-1" style={{ backgroundColor: "var(--r2-perm-r)" }} />read</span>
          <span><span className="inline-block w-2 h-2 rounded-sm mr-1" style={{ backgroundColor: "var(--r2-perm-w)" }} />write</span>
          <span><span className="inline-block w-2 h-2 rounded-sm mr-1" style={{ backgroundColor: "var(--r2-perm-x)" }} />exec</span>
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-card">
            <tr className="text-muted-foreground border-b">
              <th className="text-left py-1.5 px-3 font-medium">Name</th>
              <th className="text-left py-1.5 px-3 font-medium">VAddr</th>
              <th className="text-right py-1.5 px-3 font-medium">Size</th>
              <th className="text-right py-1.5 px-3 font-medium">VSize</th>
              <th className="text-center py-1.5 px-3 font-medium">Perm</th>
            </tr>
          </thead>
          <tbody>
            {maps.map((m, i) => (
              <tr key={i} className="border-b border-border/30 hover:bg-accent/30">
                <td className="py-1.5 px-3 font-mono">{m.name}</td>
                <td className="py-1.5 px-3 font-mono text-muted-foreground">0x{m.vaddr.toString(16)}</td>
                <td className="py-1.5 px-3 font-mono text-right">{m.size.toLocaleString()}</td>
                <td className="py-1.5 px-3 font-mono text-right">{fmt(m.size)}</td>
                <td className="py-1.5 px-3 text-center">{permBadges(m.perm)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, AlertCircle } from "lucide-react";
import { useR2Session } from "@/lib/use-r2-session";

interface BinaryEntry {
  name: string;
  vaddr: string;
  size: number;
  type: string;
}

export function BinariesTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { cmd, isReady, error: sessionError } = useR2Session();
  const [bins, setBins] = useState<BinaryEntry[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!isReady) return;
    setLoading(true);
    setError(null);
    try {
      const raw = await cmd("ilj");
      const arr = JSON.parse(raw);
      const entries: BinaryEntry[] = (Array.isArray(arr) ? arr : []).map((b: any) => ({
        name: typeof b === "string" ? b : (b.name ?? b.string ?? ""),
        vaddr: b.vaddr != null ? `0x${b.vaddr.toString(16)}` : "",
        size: b.size ?? 0,
        type: b.type ?? "",
      }));
      setBins(entries);
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
        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_loading_libs")}
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

  return (
    <div className="h-full overflow-auto">
      <table className="w-full text-xs">
        <thead className="sticky top-0 bg-card">
          <tr className="text-muted-foreground border-b">
            <th className="text-left py-1.5 px-3 font-medium">#</th>
            <th className="text-left py-1.5 px-3 font-medium">Name</th>
            {bins.some((b) => b.vaddr) && <th className="text-left py-1.5 px-3 font-medium">Address</th>}
            {bins.some((b) => b.size > 0) && <th className="text-right py-1.5 px-3 font-medium">Size</th>}
          </tr>
        </thead>
        <tbody>
          {bins.map((b, i) => (
            <tr key={i} className="border-b border-border/30 hover:bg-accent/30">
              <td className="py-1.5 px-3 text-muted-foreground">{i + 1}</td>
              <td className="py-1.5 px-3 font-mono truncate max-w-md">{b.name}</td>
              {bins.some((x) => x.vaddr) && <td className="py-1.5 px-3 font-mono text-muted-foreground">{b.vaddr}</td>}
              {bins.some((x) => x.size > 0) && <td className="py-1.5 px-3 font-mono text-right">{b.size > 0 ? b.size.toLocaleString() : ""}</td>}
            </tr>
          ))}
        </tbody>
      </table>
      {bins.length === 0 && (
        <div className="flex items-center justify-center h-32 text-xs text-muted-foreground">
          {t("r2_no_linked_libs")}
        </div>
      )}
    </div>
  );
}

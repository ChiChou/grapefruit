import { useCallback, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, Search } from "lucide-react";
import { useR2Session } from "@/lib/use-r2-session";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { useR2 } from "@/context/R2Context";

type Mode = "string" | "hex" | "rop" | "asm";

interface Result {
  addr: string;
  content: string;
}

const MODES: { value: Mode; labelKey: string; placeholderKey: string }[] = [
  { value: "string", labelKey: "r2_string", placeholderKey: "r2_search_string" },
  { value: "hex", labelKey: "r2_hex", placeholderKey: "r2_search_hex" },
  { value: "rop", labelKey: "r2_rop", placeholderKey: "r2_search_rop" },
  { value: "asm", labelKey: "r2_asm", placeholderKey: "r2_search_asm" },
];

function buildCmd(m: Mode, query: string): string {
  switch (m) {
    case "string": return `/j ${query}`;
    case "hex": return `/xj ${query.replace(/\s+/g, "")}`;
    case "rop": return query.trim() ? `/R/${query}` : "/Rj";
    case "asm": return `/aj ${query}`;
  }
}

function parseResults(_mode: Mode, raw: string): Result[] {
  // Try JSON first
  try {
    const arr = JSON.parse(raw);
    if (Array.isArray(arr)) {
      return arr.map((r: any) => ({
        addr: r.offset != null ? `0x${r.offset.toString(16)}` : (r.addr ?? ""),
        content: r.data ?? r.opstr ?? r.string ?? r.code ?? JSON.stringify(r),
      }));
    }
  } catch {}

  // Fallback: parse text output line by line
  const results: Result[] = [];
  for (const line of raw.split("\n")) {
    const match = line.match(/^\s*(0x[0-9a-fA-F]+)\s+(.*)$/);
    if (match) {
      results.push({ addr: match[1], content: match[2] });
    }
  }
  return results;
}

export function R2SearchTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { cmd, isReady } = useR2Session();
  const r2 = useR2();
  const [mode, setMode] = useState<Mode>("string");
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<Result[]>([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);

  const search = useCallback(async () => {
    if (!isReady || !query.trim()) return;
    setLoading(true);
    setSearched(true);
    try {
      const raw = await cmd(buildCmd(mode, query));
      setResults(parseResults(mode, raw));
    } catch {
      setResults([]);
    } finally {
      setLoading(false);
    }
  }, [cmd, isReady, mode, query]);

  const modeInfo = MODES.find((m) => m.value === mode)!;
  const modePlaceholder = t(modeInfo.placeholderKey);

  return (
    <div className="h-full flex flex-col">
      <div className="p-2 border-b space-y-2">
        <div className="flex gap-1">
          {MODES.map((m) => (
            <button
              key={m.value}
              type="button"
              onClick={() => setMode(m.value)}
              className={`px-2 py-1 text-xs rounded transition-colors ${
                mode === m.value ? "bg-primary text-primary-foreground" : "bg-muted hover:bg-accent"
              }`}
            >
              {t(m.labelKey)}
            </button>
          ))}
        </div>
        <form
          onSubmit={(e) => { e.preventDefault(); search(); }}
          className="flex gap-2"
        >
          <div className="relative flex-1">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <Input
              placeholder={modePlaceholder}
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="pl-8 h-8 text-xs font-mono"
            />
          </div>
          <Button type="submit" size="sm" disabled={loading || !isReady || !query.trim()}>
            {loading ? <Loader2 className="h-3 w-3 animate-spin" /> : t("r2_search")}
          </Button>
        </form>
      </div>

      <div className="flex-1 overflow-auto">
        {loading ? (
          <div className="flex items-center justify-center h-32 text-muted-foreground">
            <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_searching")}
          </div>
        ) : results.length > 0 ? (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-card">
              <tr className="text-muted-foreground border-b">
                <th className="text-left py-1.5 px-3 font-medium w-32">Address</th>
                <th className="text-left py-1.5 px-3 font-medium">Match</th>
              </tr>
            </thead>
            <tbody>
              {results.map((r, i) => (
                <tr
                  key={i}
                  className="border-b border-border/30 hover:bg-accent/30 cursor-pointer"
                  onClick={() => r2.seek(r.addr, r.content.slice(0, 40))}
                >
                  <td className="py-1.5 px-3 font-mono text-muted-foreground">{r.addr}</td>
                  <td className="py-1.5 px-3 font-mono truncate max-w-lg">{r.content}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : searched ? (
          <div className="flex items-center justify-center h-32 text-xs text-muted-foreground">
            {t("r2_no_results")}
          </div>
        ) : (
          <div className="flex items-center justify-center h-32 text-xs text-muted-foreground">
            {t("r2_search_query")}
          </div>
        )}
        {results.length > 0 && (
          <div className="px-3 py-1.5 text-[10px] text-muted-foreground border-t">
            {results.length} result{results.length !== 1 ? "s" : ""}
          </div>
        )}
      </div>
    </div>
  );
}

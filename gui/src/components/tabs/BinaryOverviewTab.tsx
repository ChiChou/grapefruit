import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, AlertCircle } from "lucide-react";
import { useR2Session } from "@/lib/use-r2-session";
import { Badge } from "@/components/ui/badge";

interface BinInfo {
  arch: string;
  bits: number;
  os: string;
  machine: string;
  type: string;
  cls: string;
  lang: string;
  compiler: string;
  stripped: boolean;
  canary: boolean;
  nx: boolean;
  pic: boolean;
  relocs: boolean;
  endian: string;
  baddr: string;
  bintype: string;
}

interface Section {
  name: string;
  size: number;
  vsize: number;
  vaddr: string;
  paddr: string;
  perm: string;
  entropy?: number;
}

interface EntryPoint {
  vaddr: string;
  paddr: string;
  type: string;
}

interface FileHash {
  type: string;
  hash: string;
}

interface Overview {
  info: BinInfo;
  sections: Section[];
  entries: EntryPoint[];
  hashes: FileHash[];
  entropy: number[];
}

function permBadge(perm: string) {
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

function boolBadge(label: string, val: boolean) {
  return (
    <Badge variant={val ? "default" : "outline"} className="text-[10px] px-1.5 py-0">
      {label}: {val ? "Yes" : "No"}
    </Badge>
  );
}

function EntropyBar({ values }: { values: number[] }) {
  if (!values.length) return null;
  const h = 32;
  const w = values.length;
  const style = typeof window !== "undefined" ? getComputedStyle(document.documentElement) : null;
  const lo = style?.getPropertyValue("--r2-entropy-lo").trim() || "rgb(0,200,80)";
  const hi = style?.getPropertyValue("--r2-entropy-hi").trim() || "rgb(255,0,80)";
  return (
    <svg viewBox={`0 0 ${w} ${h}`} className="w-full h-8 rounded bg-muted" preserveAspectRatio="none">
      <defs>
        <linearGradient id="entropy-grad" x1="0" y1="1" x2="0" y2="0">
          <stop offset="0%" stopColor={lo} />
          <stop offset="100%" stopColor={hi} />
        </linearGradient>
      </defs>
      {values.map((v, i) => {
        const clamped = Math.min(Math.max(v, 0), 8) / 8;
        return (
          <rect key={i} x={i} y={h - clamped * h} width={1} height={clamped * h} fill="url(#entropy-grad)" />
        );
      })}
    </svg>
  );
}

export function BinaryOverviewTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { cmd, isReady, error: sessionError } = useR2Session();
  const [data, setData] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    if (!isReady) return;
    setLoading(true);
    setError(null);
    try {
      const [infoRaw, sectRaw, entryRaw, hashRaw, entropyRaw] = await Promise.all([
        cmd("iIj"),
        cmd("iSj"),
        cmd("iEj"),
        cmd("itj"),
        cmd("p=ej 100"),
      ]);

      let info: BinInfo = {} as BinInfo;
      try {
        const j = JSON.parse(infoRaw);
        info = {
          arch: j.arch ?? "",
          bits: j.bits ?? 0,
          os: j.os ?? "",
          machine: j.machine ?? "",
          type: j.type ?? "",
          cls: j.class ?? "",
          lang: j.lang ?? "",
          compiler: j.compiler ?? "",
          stripped: !!j.stripped,
          canary: !!j.canary,
          nx: !!j.nx,
          pic: !!j.pic,
          relocs: !!j.relocs,
          endian: j.endian ?? "",
          baddr: j.baddr != null ? `0x${j.baddr.toString(16)}` : "",
          bintype: j.bintype ?? "",
        };
      } catch {}

      let sections: Section[] = [];
      try {
        const arr = JSON.parse(sectRaw);
        sections = (Array.isArray(arr) ? arr : []).map((s: any) => ({
          name: s.name ?? "",
          size: s.size ?? 0,
          vsize: s.vsize ?? 0,
          vaddr: s.vaddr != null ? `0x${s.vaddr.toString(16)}` : "",
          paddr: s.paddr != null ? `0x${s.paddr.toString(16)}` : "",
          perm: s.perm ?? "",
          entropy: s.entropy,
        }));
      } catch {}

      let entries: EntryPoint[] = [];
      try {
        const arr = JSON.parse(entryRaw);
        entries = (Array.isArray(arr) ? arr : []).map((e: any) => ({
          vaddr: e.vaddr != null ? `0x${e.vaddr.toString(16)}` : "",
          paddr: e.paddr != null ? `0x${e.paddr.toString(16)}` : "",
          type: e.type ?? "program",
        }));
      } catch {}

      let hashes: FileHash[] = [];
      try {
        const j = JSON.parse(hashRaw);
        if (Array.isArray(j)) {
          hashes = j.map((h: any) => ({ type: h.type ?? "", hash: h.hash ?? "" }));
        } else if (j && typeof j === "object") {
          for (const [type, hash] of Object.entries(j)) {
            if (typeof hash === "string") hashes.push({ type, hash });
          }
        }
      } catch {}

      let entropy: number[] = [];
      try {
        const arr = JSON.parse(entropyRaw);
        if (Array.isArray(arr)) {
          entropy = arr.map((e: any) => typeof e === "number" ? e : (e?.entropy ?? 0));
        }
      } catch {}

      setData({ info, sections, entries, hashes, entropy });
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
        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_loading_binary")}
      </div>
    );
  }

  if (error || !data) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-2 text-center">
          <AlertCircle className="h-6 w-6 text-destructive" />
          <p className="text-xs font-mono">{error ?? "No data"}</p>
        </div>
      </div>
    );
  }

  const { info, sections, entries, hashes, entropy } = data;

  return (
    <div className="h-full overflow-auto p-4 space-y-4">
      <div className="grid grid-cols-2 gap-4">
        <Card title={t("r2_general")}>
          <Row label={t("r2_architecture")} value={`${info.arch} (${info.bits}-bit)`} />
          <Row label="OS" value={info.os} />
          <Row label={t("r2_format")} value={`${info.bintype} / ${info.type}`} />
          <Row label="Class" value={info.cls} />
          <Row label={t("r2_machine")} value={info.machine} />
          <Row label={t("r2_endian")} value={info.endian} />
          <Row label={t("r2_base_addr")} value={info.baddr} mono />
        </Card>

        <Card title={t("r2_compiler")}>
          <Row label={t("r2_language")} value={info.lang} />
          <Row label={t("r2_compiler")} value={info.compiler} />
          <div className="flex flex-wrap gap-1 mt-1">
            {boolBadge("Stripped", info.stripped)}
            {boolBadge("Canary", info.canary)}
            {boolBadge("NX", info.nx)}
            {boolBadge("PIC", info.pic)}
            {boolBadge("Relocs", info.relocs)}
          </div>
        </Card>
      </div>

      {hashes.length > 0 && (
        <Card title={t("r2_hashes")}>
          {hashes.map((h) => (
            <Row key={h.type} label={h.type.toUpperCase()} value={h.hash} mono />
          ))}
        </Card>
      )}

      {entropy.length > 0 && (
        <Card title={t("r2_entropy")}>
          <EntropyBar values={entropy} />
        </Card>
      )}

      {entries.length > 0 && (
        <Card title={`${t("r2_entry_points")} (${entries.length})`}>
          <div className="font-mono text-xs space-y-0.5">
            {entries.map((e, i) => (
              <div key={i} className="flex gap-4">
                <span className="text-muted-foreground">{e.vaddr}</span>
                <span>{e.type}</span>
              </div>
            ))}
          </div>
        </Card>
      )}

      <Card title={`${t("sections")} (${sections.length})`}>
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="text-muted-foreground border-b">
                <th className="text-left py-1 pr-3 font-medium">Name</th>
                <th className="text-left py-1 pr-3 font-medium">VAddr</th>
                <th className="text-right py-1 pr-3 font-medium">Size</th>
                <th className="text-right py-1 pr-3 font-medium">VSize</th>
                <th className="text-center py-1 font-medium">Perm</th>
              </tr>
            </thead>
            <tbody>
              {sections.map((s, i) => (
                <tr key={i} className="border-b border-border/30 hover:bg-accent/30">
                  <td className="py-1 pr-3 font-mono">{s.name}</td>
                  <td className="py-1 pr-3 font-mono text-muted-foreground">{s.vaddr}</td>
                  <td className="py-1 pr-3 font-mono text-right">{s.size.toLocaleString()}</td>
                  <td className="py-1 pr-3 font-mono text-right">{s.vsize.toLocaleString()}</td>
                  <td className="py-1 text-center">{permBadge(s.perm)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function Card({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border bg-card p-3">
      <h3 className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">{title}</h3>
      {children}
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  if (!value) return null;
  return (
    <div className="flex items-baseline gap-2 py-0.5 text-xs">
      <span className="text-muted-foreground shrink-0">{label}</span>
      <span className={`truncate ${mono ? "font-mono" : ""}`}>{value}</span>
    </div>
  );
}

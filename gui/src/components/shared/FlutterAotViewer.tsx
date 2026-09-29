import { useEffect, useMemo, useState } from "react";
import { useTranslation } from "react-i18next";
import { AlertTriangle, Box, Braces, Code2, Link2, PackageSearch } from "lucide-react";

import type {
  FlutterAnalysis,
  FlutterClass,
  FlutterFunction,
} from "@/lib/flutter-aot";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

interface Props {
  data: FlutterAnalysis;
  disassemble: (addr: number) => Promise<string>;
}

function hex(value?: number) {
  return value == null ? "—" : `0x${value.toString(16)}`;
}

function Summary({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="rounded-md border bg-card px-4 py-3">
      <div className="text-[11px] uppercase tracking-wide text-muted-foreground">{label}</div>
      <div className="mt-1 truncate font-mono text-sm" title={String(value)}>{value}</div>
    </div>
  );
}

function Functions({ rows, disassemble }: { rows: FlutterFunction[]; disassemble: Props["disassemble"] }) {
  const { t } = useTranslation();
  const [selected, setSelected] = useState<FlutterFunction | null>(null);
  const [asm, setAsm] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!selected) return;
    let cancelled = false;
    setLoading(true);
    disassemble(selected.addr)
      .then((value) => { if (!cancelled) setAsm(value); })
      .catch((error: unknown) => {
        if (!cancelled) setAsm(error instanceof Error ? error.message : String(error));
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [selected, disassemble]);

  return (
    <div className="grid h-full min-h-0 grid-cols-1 xl:grid-cols-[minmax(0,1fr)_minmax(360px,0.8fr)]">
      <div className="overflow-auto border-r">
        <Table>
          <TableHeader className="sticky top-0 z-10 bg-background">
            <TableRow><TableHead>{t("address")}</TableHead><TableHead>{t("name")}</TableHead><TableHead>{t("size")}</TableHead></TableRow>
          </TableHeader>
          <TableBody>
            {rows.map((fn) => (
              <TableRow
                key={`${fn.addr}-${fn.name}`}
                className="cursor-pointer"
                data-state={selected === fn ? "selected" : undefined}
                onClick={() => setSelected(fn)}
              >
                <TableCell className="font-mono text-xs">{hex(fn.addr)}</TableCell>
                <TableCell className="max-w-md truncate" title={fn.signature ?? fn.name}>{fn.name}</TableCell>
                <TableCell className="font-mono text-xs">{fn.size ?? "—"}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      <div className="min-h-48 overflow-auto bg-muted/20 p-4">
        {selected ? (
          <>
            <div className="mb-3 flex items-center justify-between gap-3">
              <div className="min-w-0">
                <div className="truncate text-sm font-medium">{selected.name}</div>
                <div className="font-mono text-xs text-muted-foreground">{hex(selected.addr)}</div>
              </div>
              {selected.signature && <Badge variant="outline">{selected.signature}</Badge>}
            </div>
            <pre className="whitespace-pre-wrap font-mono text-xs leading-5 text-foreground/90">
              {loading ? t("loading") : asm}
            </pre>
          </>
        ) : <div className="text-sm text-muted-foreground">{t("flutter_select_function")}</div>}
      </div>
    </div>
  );
}

function Classes({ rows }: { rows: FlutterClass[] }) {
  const { t } = useTranslation();
  const [selected, setSelected] = useState<FlutterClass | null>(rows[0] ?? null);
  return (
    <div className="grid h-full min-h-0 grid-cols-1 xl:grid-cols-[340px_minmax(0,1fr)]">
      <div className="overflow-auto border-r">
        {rows.map((item, index) => (
          <button
            key={`${item.ref}-${item.name}-${index}`}
            className={`block w-full border-b px-3 py-2 text-left text-sm hover:bg-muted/50 ${selected === item ? "bg-muted" : ""}`}
            onClick={() => setSelected(item)}
          >
            <div className="truncate font-medium">{item.name ?? `class_${item.ref}`}</div>
            <div className="truncate text-xs text-muted-foreground">{item.library?.name ?? item.super?.name ?? ""}</div>
          </button>
        ))}
      </div>
      <div className="overflow-auto p-4">
        {selected && (
          <div className="space-y-5">
            <div>
              <h3 className="text-lg font-semibold">{selected.name ?? `class_${selected.ref}`}</h3>
              <div className="mt-1 flex flex-wrap gap-2 text-xs text-muted-foreground">
                <span>{t("flutter_library")}: {selected.library?.name ?? "—"}</span>
                <span>{t("flutter_super")}: {selected.super?.name ?? "—"}</span>
                <span>{t("size")}: {selected.layout?.instance_size ?? "—"}</span>
              </div>
            </div>
            <section>
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t("flutter_fields")}</h4>
              <div className="rounded-md border">
                {(selected.fields ?? []).map((field, index) => (
                  <div key={`${field.name}-${index}`} className="grid grid-cols-[1fr_1fr_auto] gap-3 border-b px-3 py-2 text-xs last:border-0">
                    <span className="truncate font-medium">{field.name ?? "—"}</span>
                    <span className="truncate text-muted-foreground">{field.type ?? "dynamic"}</span>
                    <span className="font-mono text-muted-foreground">{hex(field.offset)}</span>
                  </div>
                ))}
                {!selected.fields?.length && <div className="p-3 text-xs text-muted-foreground">{t("no_results")}</div>}
              </div>
            </section>
            <section>
              <h4 className="mb-2 text-xs font-semibold uppercase tracking-wide text-muted-foreground">{t("flutter_methods")}</h4>
              <div className="rounded-md border">
                {(selected.methods ?? []).map((method, index) => (
                  <div key={`${method.entry}-${method.name}-${index}`} className="grid grid-cols-[auto_1fr_auto] gap-3 border-b px-3 py-2 text-xs last:border-0">
                    <span className="font-mono text-muted-foreground">{hex(method.entry)}</span>
                    <span className="truncate font-medium" title={method.signature}>{method.name ?? "—"}</span>
                    <span className="text-muted-foreground">{method.kind ?? ""}</span>
                  </div>
                ))}
                {!selected.methods?.length && <div className="p-3 text-xs text-muted-foreground">{t("no_results")}</div>}
              </div>
            </section>
          </div>
        )}
      </div>
    </div>
  );
}

export function FlutterAotViewer({ data, disassemble }: Props) {
  const { t } = useTranslation();
  const [query, setQuery] = useState("");
  const needle = query.trim().toLowerCase();
  const functions = useMemo(
    () => data.functions.filter((item) => !needle || item.name.toLowerCase().includes(needle) || hex(item.addr).includes(needle)),
    [data.functions, needle],
  );
  const classes = useMemo(
    () => data.classes.filter((item) => !needle || item.name?.toLowerCase().includes(needle) || item.library?.name?.toLowerCase().includes(needle)),
    [data.classes, needle],
  );
  const strings = useMemo(
    () => data.strings.filter((item) => !needle || item.value?.toLowerCase().includes(needle) || item.category?.toLowerCase().includes(needle)),
    [data.strings, needle],
  );
  const xrefs = useMemo(
    () => data.xrefs.filter((item) => !needle || JSON.stringify(item).toLowerCase().includes(needle)),
    [data.xrefs, needle],
  );
  const components = useMemo(
    () => (data.sbom.components ?? []).filter((item) => !needle || item.name.toLowerCase().includes(needle) || item.type.toLowerCase().includes(needle)),
    [data.sbom.components, needle],
  );

  return (
    <Tabs defaultValue="overview" className="h-full min-h-0 gap-0">
      <div className="flex h-11 shrink-0 items-center gap-3 border-b px-3">
        <TabsList variant="line" className="h-10">
          <TabsTrigger value="overview"><Box />{t("flutter_overview")}</TabsTrigger>
          <TabsTrigger value="functions"><Code2 />{t("flutter_functions")} <Badge variant="secondary">{data.functions.length}</Badge></TabsTrigger>
          <TabsTrigger value="classes"><Braces />{t("classes")} <Badge variant="secondary">{data.classes.length}</Badge></TabsTrigger>
          <TabsTrigger value="strings">{t("flutter_strings")} <Badge variant="secondary">{data.strings.length}</Badge></TabsTrigger>
          <TabsTrigger value="xrefs"><Link2 />{t("flutter_xrefs")} <Badge variant="secondary">{data.xrefs.length}</Badge></TabsTrigger>
          <TabsTrigger value="components"><PackageSearch />{t("components")} <Badge variant="secondary">{data.sbom.components?.length ?? 0}</Badge></TabsTrigger>
        </TabsList>
        <Input value={query} onChange={(event) => setQuery(event.target.value)} placeholder={t("search")} className="ml-auto h-8 w-64" />
      </div>

      <TabsContent value="overview" className="min-h-0 overflow-auto p-5">
        <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Summary label="Dart" value={data.header.dart_version ?? "unknown"} />
          <Summary label={t("flutter_snapshot_hash")} value={data.header.hash ?? "—"} />
          <Summary label={t("r2_architecture")} value={`${data.header.tag_style ?? "unknown"} / cws ${data.header.cws ?? "?"}`} />
          <Summary label={t("r2_format")} value={data.header.container?.kind ?? (data.header.single_snapshot ? "single snapshot" : "AOT snapshot")} />
          <Summary label="VM data" value={hex(data.header.vm_data)} />
          <Summary label="VM instructions" value={hex(data.header.vm_instr)} />
          <Summary label="Isolate data" value={hex(data.header.iso_data)} />
          <Summary label="Isolate instructions" value={hex(data.header.iso_instr)} />
        </div>
        <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
          <Summary label={t("flutter_functions")} value={data.functions.length} />
          <Summary label={t("classes")} value={data.classes.length} />
          <Summary label={t("flutter_strings")} value={data.strings.length} />
          <Summary label={t("flutter_xrefs")} value={data.xrefs.length} />
        </div>
        {!data.sbom.complete && (
          <div className="mt-5 flex gap-3 rounded-md border border-amber-500/30 bg-amber-500/5 p-4 text-sm">
            <AlertTriangle className="h-5 w-5 shrink-0 text-amber-500" />
            <div><div className="font-medium">{t("flutter_sbom_partial")}</div><div className="mt-1 text-muted-foreground">{data.sbom.note}</div></div>
          </div>
        )}
      </TabsContent>

      <TabsContent value="functions" className="min-h-0 overflow-hidden"><Functions rows={functions} disassemble={disassemble} /></TabsContent>
      <TabsContent value="classes" className="min-h-0 overflow-hidden"><Classes rows={classes} /></TabsContent>
      <TabsContent value="strings" className="min-h-0 overflow-auto">
        <Table><TableHeader className="sticky top-0 z-10 bg-background"><TableRow><TableHead>{t("address")}</TableHead><TableHead>{t("value")}</TableHead><TableHead>{t("type")}</TableHead><TableHead>{t("size")}</TableHead></TableRow></TableHeader><TableBody>
          {strings.map((item, index) => <TableRow key={`${item.ref}-${index}`}><TableCell className="font-mono text-xs">{hex(item.addr)}</TableCell><TableCell className="max-w-2xl whitespace-normal break-all">{item.value ?? ""}</TableCell><TableCell>{item.category ?? "—"}</TableCell><TableCell className="font-mono text-xs">{item.len}</TableCell></TableRow>)}
        </TableBody></Table>
      </TabsContent>
      <TabsContent value="xrefs" className="min-h-0 overflow-auto">
        <Table><TableHeader className="sticky top-0 z-10 bg-background"><TableRow><TableHead>{t("type")}</TableHead><TableHead>{t("flutter_source")}</TableHead><TableHead>{t("flutter_target")}</TableHead><TableHead>{t("flutter_origin")}</TableHead></TableRow></TableHeader><TableBody>
          {xrefs.map((item, index) => <TableRow key={`${item.kind}-${index}`}><TableCell>{item.kind}</TableCell><TableCell>{item.src.name ?? item.src.type} <span className="font-mono text-xs text-muted-foreground">{hex(item.src.addr)}</span></TableCell><TableCell>{item.dst.name ?? item.dst.type} <span className="font-mono text-xs text-muted-foreground">{hex(item.dst.addr)}</span></TableCell><TableCell>{item.origin}</TableCell></TableRow>)}
        </TableBody></Table>
      </TabsContent>
      <TabsContent value="components" className="min-h-0 overflow-auto">
        <Table><TableHeader className="sticky top-0 z-10 bg-background"><TableRow><TableHead>{t("name")}</TableHead><TableHead>{t("type")}</TableHead><TableHead>{t("version")}</TableHead><TableHead>{t("flutter_confidence")}</TableHead><TableHead>{t("flutter_evidence")}</TableHead></TableRow></TableHeader><TableBody>
          {components.map((item, index) => <TableRow key={`${item.type}-${item.name}-${index}`}><TableCell className="font-medium">{item.name}</TableCell><TableCell>{item.type}</TableCell><TableCell>{item.version ?? "—"}</TableCell><TableCell>{item.confidence}%</TableCell><TableCell className="max-w-xl whitespace-normal text-muted-foreground">{item.evidence ?? item.source ?? "—"}</TableCell></TableRow>)}
        </TableBody></Table>
      </TabsContent>
    </Tabs>
  );
}

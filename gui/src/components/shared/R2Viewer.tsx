import { activate } from "@/lib/keyboard";
/**
 * Radare2 binary viewer: classes/functions, strings, disassembly, CFG, offline decompilation.
 * Supports DEX, native binaries, and other formats radare2 can analyze.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Loader2,
  Search,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronRight as ChevronExpand,
  Binary,
  Pencil,
} from "lucide-react";
import { useVirtualizer } from "@tanstack/react-virtual";
import * as decompiler from "@/lib/decompiler";
import { Decompiler } from "./Decompiler";

import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { CFGView, type CFGNode, type CFGEdge } from "@/components/shared/CFGView";
import { DisassemblyMinimap } from "@/components/shared/DisassemblyMinimap";
import { RenameDialog } from "@/components/shared/RenameDialog";
import type { DexClass, DexMethod, DexString, StringXref, R2Function } from "@/lib/r2";

import "../tabs/DisassemblyTab.css";

export interface R2ViewerProps {
  binType: string;
  arch: string;
  bits: number;
  data: ArrayBuffer;
  classes: DexClass[];
  functions: R2Function[];
  strings: DexString[];
  cmd: (command: string, output?: "plain" | "html") => Promise<string>;
  disassemble: (address: string, output?: "plain" | "html") => Promise<string>;
  cfg: (address: string) => Promise<{ nodes: CFGNode[]; edges: CFGEdge[] } | null>;
  xrefs: (vaddr: number) => Promise<StringXref[]>;
  funcXrefs: (address: string) => Promise<StringXref[]>;
  /** Key for persisting view state across reload */
  storageKey?: string;
}

type LeftTab = "classes" | "functions" | "strings" | "maps";

type ViewMode = "disassembly" | "graph" | "split" | "decompiler";

interface SectionEntry {
  name: string;
  vaddr: number;
  size: number;
  perm: string;
}

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function loadState(key: string | undefined) {
  if (!key) return null;
  try {
    const raw = localStorage.getItem(`r2v:${key}`);
    return raw ? JSON.parse(raw) : null;
  } catch { return null; }
}

function saveState(key: string | undefined, patch: Record<string, any>) {
  if (!key) return;
  const prev = loadState(key) ?? {};
  localStorage.setItem(`r2v:${key}`, JSON.stringify({ ...prev, ...patch }));
}

export function R2Viewer({
  binType,
  arch,
  bits,
  data,
  classes,
  functions,
  strings,
  cmd,
  disassemble,
  cfg,
  xrefs,
  funcXrefs,
  storageKey,
}: R2ViewerProps) {
  const { t } = useTranslation();

  const isDex = arch === "dalvik" || /dex/i.test(binType);
  const saved = useRef(loadState(storageKey));

  const [leftTab, setLeftTab] = useState<LeftTab>(() => saved.current?.leftTab ?? "functions");
  const [classSearch, setClassSearch] = useState("");
  const [funcSearch, setFuncSearch] = useState("");
  const [strSearch, setStrSearch] = useState("");

  const [selectedClass, setSelectedClass] = useState<DexClass | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<DexMethod | null>(null);
  const [selectedString, setSelectedString] = useState<DexString | null>(null);
  const [expandedClasses, setExpandedClasses] = useState<Set<string>>(new Set());

  const [viewMode, setViewModeState] = useState<ViewMode>(() => ["disassembly", "graph", "split", ...(isDex || decompiler.target(arch, bits) ? ["decompiler"] : [])].includes(saved.current?.viewMode) ? saved.current.viewMode : "disassembly");
  const viewModeRef = useRef(viewMode);
  const setViewMode = useCallback((m: ViewMode) => { viewModeRef.current = m; setViewModeState(m); }, []);
  const [codeHtml, setCodeHtml] = useState("");
  const [codeLoading, setCodeLoading] = useState(false);
  const [showBytes, setShowBytes] = useState(false);

  const [renameOpen, setRenameOpen] = useState(false);

  const [cfgData, setCfgData] = useState<{ nodes: CFGNode[]; edges: CFGEdge[] } | null>(null);
  const [cfgLoading, setCfgLoading] = useState(false);

  const [sections, setSections] = useState<SectionEntry[]>([]);

  const [stringXrefList, setStringXrefList] = useState<StringXref[]>([]);
  const [methodXrefList, setMethodXrefList] = useState<StringXref[]>([]);

  // Navigation history
  const historyRef = useRef<{ label: string; cls: DexClass; method?: DexMethod }[]>([]);
  const historyIdx = useRef(-1);
  const navigatingRef = useRef(false);
  const [, setHistoryTick] = useState(0);

  const filteredClasses = useMemo(() => {
    if (!classSearch.trim()) return classes;
    const q = classSearch.toLowerCase();
    return classes.filter((c) => c.name.toLowerCase().includes(q));
  }, [classes, classSearch]);

  const filteredFunctions = useMemo(() => {
    if (!funcSearch.trim()) return functions;
    const q = funcSearch.toLowerCase();
    return functions.filter((f) => f.name.toLowerCase().includes(q));
  }, [functions, funcSearch]);

  const sectionsLoaded = useRef(false);
  const loadSections = useCallback(async () => {
    if (sectionsLoaded.current) return;
    sectionsLoaded.current = true;
    try {
      const raw = await cmd("iSj");
      const arr = JSON.parse(raw);
      setSections(
        (Array.isArray(arr) ? arr : [])
          .filter((s: any) => s.size > 0)
          .map((s: any) => ({
            name: s.name ?? "",
            vaddr: s.vaddr ?? 0,
            size: s.size ?? 0,
            perm: s.perm ?? "",
          })),
      );
    } catch {}
  }, [cmd]);

  const filteredStrings = useMemo(() => {
    if (!strSearch.trim()) return strings;
    const q = strSearch.toLowerCase();
    return strings.filter((s) => s.value.toLowerCase().includes(q));
  }, [strings, strSearch]);

  const loadDisassembly = useCallback(
    async (method: DexMethod) => {
      setCodeLoading(true);
      setCfgData(null);
      try {
        let html: string;
        if (showBytes) {
          html = await cmd(`e asm.bytes=true; e asm.nbytes=8; s ${method.addr}; af; pdf`, "html");
        } else {
          html = await disassemble(method.addr, "html");
        }
        setCodeHtml(html);
      } catch {
        setCodeHtml("<pre>; Failed to disassemble</pre>");
      } finally {
        setCodeLoading(false);
      }
    },
    [disassemble, cmd, showBytes],
  );

  const loadCfg = useCallback(
    async (method: DexMethod) => {
      setCfgLoading(true);
      try {
        const data = await cfg(method.addr);
        setCfgData(data);
      } catch {
        setCfgData(null);
      } finally {
        setCfgLoading(false);
      }
    },
    [cfg],
  );

  const selectMethod = useCallback(
    (cls: DexClass, method: DexMethod) => {
      if (!navigatingRef.current) {
        historyRef.current = historyRef.current.slice(0, historyIdx.current + 1);
        historyRef.current.push({ label: `${cls.name}.${method.name}`, cls, method });
        historyIdx.current = historyRef.current.length - 1;
        setHistoryTick((t) => t + 1);
      }

      setSelectedClass(cls);
      setSelectedMethod(method);
      setSelectedString(null);

      funcXrefs(method.addr).then(setMethodXrefList);

      const mode = viewModeRef.current;
      if (mode === "graph" || mode === "split") {
        loadDisassembly(method);
        loadCfg(method);
      } else {
        loadDisassembly(method);
      }
    },
    [loadDisassembly, loadCfg, funcXrefs],
  );

  const selectClass = useCallback((cls: DexClass) => {
    setSelectedClass(cls);
    setSelectedMethod(null);
    setSelectedString(null);

    // Show class summary as HTML
    const lines = [`<b>${escapeHtml(cls.name)}</b> :: ${escapeHtml(cls.superclass)}`];
    if (cls.fields.length > 0) {
      lines.push("", "<b>Fields:</b>");
      for (const f of cls.fields) lines.push(`  ${escapeHtml(f.flags)} ${escapeHtml(f.name)}`);
    }
    lines.push("", `<b>Methods (${cls.methods.length}):</b>`);
    for (const m of cls.methods) lines.push(`  ${escapeHtml(m.flags)} ${escapeHtml(m.name)}`);
    setCodeHtml(`<pre>${lines.join("\n")}</pre>`);
  }, []);

  const selectString = useCallback(
    async (str: DexString) => {
      setSelectedString(str);
      setSelectedClass(null);
      setSelectedMethod(null);
      const refs = await xrefs(str.vaddr);
      setStringXrefList(refs);
    },
    [xrefs],
  );

  // Restore selected function on mount (before persistence kicks in)
  const restored = useRef(false);
  useEffect(() => {
    if (restored.current || !functions.length) return;
    restored.current = true;
    const s = saved.current;
    if (s?.fnAddr) {
      const fn = functions.find((f) => f.addr === s.fnAddr);
      if (fn) {
        const pseudo: DexMethod = { addr: fn.addr, index: 0, flags: "", signature: fn.name, name: fn.name };
        const pseudoCls: DexClass = { addr: fn.addr, name: fn.name, superclass: "", size: fn.size, methods: [pseudo], fields: [] };
        selectMethod(pseudoCls, pseudo);
      }
    }
    // Load sections if maps tab was persisted
    if (s?.leftTab === "maps") loadSections();
  }, [functions, selectMethod, loadSections]);

  // Persist view state (only after initial restore)
  useEffect(() => {
    if (!restored.current) return;
    saveState(storageKey, { leftTab, viewMode, fnAddr: selectedMethod?.addr });
  }, [storageKey, leftTab, viewMode, selectedMethod?.addr]);

  // Load sections when switching to maps tab
  useEffect(() => {
    if (leftTab === "maps") loadSections();
  }, [leftTab, loadSections]);

  const changeViewMode = useCallback(
    (mode: ViewMode) => {
      setViewMode(mode);
      if (!selectedMethod || !selectedClass) return;
      if (mode === "graph") loadCfg(selectedMethod);
      else if (mode === "split") {
        loadDisassembly(selectedMethod);
        loadCfg(selectedMethod);
      } else if (mode !== "decompiler") loadDisassembly(selectedMethod);
    },
    [selectedMethod, selectedClass, loadDisassembly, loadCfg, setViewMode],
  );

  const cpu = decompiler.target(arch, bits);
  const load = useCallback(async (signal: AbortSignal) => {
    if ((!cpu && !isDex) || !selectedMethod) throw new Error("Unsupported architecture");
    return decompiler.decompile({ data, target: isDex ? "dex" : cpu!, address: selectedMethod.addr }, signal);
  }, [cpu, isDex, data, selectedMethod]);

  const canGoBack = historyIdx.current > 0;
  const canGoForward = historyIdx.current < historyRef.current.length - 1;

  const goTo = useCallback(
    (idx: number) => {
      if (idx < 0 || idx >= historyRef.current.length) return;
      historyIdx.current = idx;
      navigatingRef.current = true;
      const entry = historyRef.current[idx];
      if (entry.method) selectMethod(entry.cls, entry.method);
      else selectClass(entry.cls);
      navigatingRef.current = false;
      setHistoryTick((t) => t + 1);
    },
    [selectMethod, selectClass],
  );

  const history = historyRef.current;
  const currentIdx = historyIdx.current;

  return (
    <div className="h-full flex flex-col">
      {/* Nav bar */}
      <div className="flex items-center gap-1 px-2 border-b shrink-0 h-8">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={<button className="p-1 rounded hover:bg-accent disabled:opacity-30 cursor-pointer disabled:cursor-default" disabled={!canGoBack} />}
          >
            <ChevronLeft className="h-4.5 w-4.5" />
          </DropdownMenuTrigger>
          {history.length > 1 && (
            <DropdownMenuContent>
              {history.slice(0, currentIdx).reverse().map((entry, ri) => {
                const idx = currentIdx - 1 - ri;
                return (
                  <DropdownMenuItem key={idx} onClick={() => goTo(idx)}>
                    <span className="font-mono text-xs truncate">{entry.label}</span>
                  </DropdownMenuItem>
                );
              })}
            </DropdownMenuContent>
          )}
        </DropdownMenu>
        <DropdownMenu>
          <DropdownMenuTrigger
            render={<button className="p-1 rounded hover:bg-accent disabled:opacity-30 cursor-pointer disabled:cursor-default" disabled={!canGoForward} />}
          >
            <ChevronRight className="h-4.5 w-4.5" />
          </DropdownMenuTrigger>
          {history.length > currentIdx + 1 && (
            <DropdownMenuContent>
              {history.slice(currentIdx + 1).map((entry, ri) => {
                const idx = currentIdx + 1 + ri;
                return (
                  <DropdownMenuItem key={idx} onClick={() => goTo(idx)}>
                    <span className="font-mono text-xs truncate">{entry.label}</span>
                  </DropdownMenuItem>
                );
              })}
            </DropdownMenuContent>
          )}
        </DropdownMenu>
        <div className="flex-1" />
        <Badge variant="secondary" className="text-[10px] shrink-0">
          {classes.length} classes
        </Badge>
        <Badge variant="outline" className="text-[10px] shrink-0">
          {strings.length} strings
        </Badge>
      </div>

      {/* Main area: panels + minimap */}
      <div className="flex flex-1 min-h-0">
      <ResizablePanelGroup orientation="horizontal" autoSaveId="r2-analysis" className="flex-1">
        {/* Left: classes + strings */}
        <ResizablePanel id="r2-left" defaultSize="35%" minSize="20%">
          <ResizablePanelGroup orientation="vertical" autoSaveId="r2-left-v">
          <ResizablePanel id="r2-browse" defaultSize="70%" minSize="30%">
          <Tabs value={leftTab} onValueChange={(v) => setLeftTab(v as LeftTab)} className="h-full flex flex-col">
            <TabsList variant="line" className="shrink-0">
              <TabsTrigger value="functions">{t("r2_funcs")}</TabsTrigger>
              <TabsTrigger value="classes">{t("r2_classes")}</TabsTrigger>
              <TabsTrigger value="strings">{t("r2_strings")}</TabsTrigger>
              <TabsTrigger value="maps">{t("r2_maps")}</TabsTrigger>
            </TabsList>

            {leftTab === "classes" && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="px-2 py-1.5 border-b shrink-0">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input placeholder={t("hermes_search_functions")} value={classSearch} onChange={(e) => setClassSearch(e.target.value)} className="pl-8 h-7 text-xs" />
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-1 px-0.5">{filteredClasses.length} / {classes.length}</div>
                </div>
                <ClassTree
                  classes={filteredClasses}
                  expanded={expandedClasses}
                  onToggle={(name) => setExpandedClasses((prev) => { const next = new Set(prev); if (next.has(name)) next.delete(name); else next.add(name); return next; })}
                  selectedClass={selectedClass}
                  selectedMethod={selectedMethod}
                  onSelectClass={selectClass}
                  onSelectMethod={selectMethod}
                />
              </div>
            )}

            {leftTab === "functions" && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="px-2 py-1.5 border-b shrink-0">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input placeholder={t("hermes_search_functions")} value={funcSearch} onChange={(e) => setFuncSearch(e.target.value)} className="pl-8 h-7 text-xs" />
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-1 px-0.5">{filteredFunctions.length} / {functions.length}</div>
                </div>
                <FuncList functions={filteredFunctions} selectedAddr={selectedMethod?.addr ?? null} onSelect={(fn) => {
                  // Wrap R2Function as a DexMethod-like for disassembly
                  const pseudo: DexMethod = { addr: fn.addr, index: 0, flags: "", signature: fn.name, name: fn.name };
                  const pseudoCls: DexClass = { addr: fn.addr, name: fn.name, superclass: "", size: fn.size, methods: [pseudo], fields: [] };
                  selectMethod(pseudoCls, pseudo);
                }} />
              </div>
            )}

            {leftTab === "strings" && (
              <div className="flex-1 flex flex-col overflow-hidden">
                <div className="px-2 py-1.5 border-b shrink-0">
                  <div className="relative">
                    <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                    <Input placeholder={t("hermes_search_strings")} value={strSearch} onChange={(e) => setStrSearch(e.target.value)} className="pl-8 h-7 text-xs" />
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-1 px-0.5">{filteredStrings.length} / {strings.length}</div>
                </div>
                <StringList strings={filteredStrings} selectedVaddr={selectedString?.vaddr ?? null} onSelect={selectString} />
              </div>
            )}

            {leftTab === "maps" && (
              <div className="flex-1 overflow-auto">
                {sections.length === 0 ? (
                  <div className="flex items-center justify-center h-20 text-xs text-muted-foreground">{t("r2_no_sections")}</div>
                ) : (
                  <>
                    <div className="p-2">
                      <div className="flex h-4 rounded overflow-hidden gap-px">
                        {sections.map((s, i) => {
                          const total = sections.reduce((a, x) => a + x.size, 0) || 1;
                          const pct = Math.max((s.size / total) * 100, 0.5);
                          return (
                            <div
                              key={i}
                              className="relative group"
                              style={{
                                width: `${pct}%`,
                                backgroundColor: s.perm.includes("x") ? "var(--r2-perm-x)" : s.perm.includes("w") ? "var(--r2-perm-w)" : "var(--r2-perm-r)",
                              }}
                              title={`${s.name} (${s.size.toLocaleString()}B)`}
                            />
                          );
                        })}
                      </div>
                    </div>
                    <table className="w-full text-[11px]">
                      <thead className="sticky top-0 bg-card">
                        <tr className="text-muted-foreground border-b">
                          <th className="text-left py-1 px-2 font-medium">Name</th>
                          <th className="text-left py-1 px-2 font-medium">Addr</th>
                          <th className="text-right py-1 px-2 font-medium">Size</th>
                          <th className="text-center py-1 px-2 font-medium">Perm</th>
                        </tr>
                      </thead>
                      <tbody>
                        {sections.map((s, i) => (
                          <tr key={i} className="border-b border-border/30 hover:bg-accent/30">
                            <td className="py-1 px-2 font-mono">{s.name}</td>
                            <td className="py-1 px-2 font-mono text-muted-foreground">0x{s.vaddr.toString(16)}</td>
                            <td className="py-1 px-2 font-mono text-right">{s.size.toLocaleString()}</td>
                            <td className="py-1 px-2 text-center font-mono">
                              <span className={s.perm.includes("r") ? "text-green-400" : "text-muted-foreground/30"}>r</span>
                              <span className={s.perm.includes("w") ? "text-yellow-400" : "text-muted-foreground/30"}>w</span>
                              <span className={s.perm.includes("x") ? "text-red-400" : "text-muted-foreground/30"}>x</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </>
                )}
              </div>
            )}
          </Tabs>
          </ResizablePanel>

          <ResizableHandle />

          {/* Xrefs panel */}
          <ResizablePanel id="r2-xrefs" defaultSize="30%" minSize="10%">
            {selectedString ? (
              <div className="h-full flex flex-col">
                <div className="overflow-auto p-3 border-b max-h-20">
                  <pre className="font-mono text-xs whitespace-pre-wrap break-all">
                    {selectedString.value || <span className="text-muted-foreground italic">(empty)</span>}
                  </pre>
                </div>
                <div className="flex items-center gap-1.5 px-3 py-1.5 shrink-0 border-b bg-muted/50">
                  <span className="text-[11px] font-semibold tracking-wide uppercase text-muted-foreground">{t("hermes_referenced_by")}</span>
                  <span className="text-[10px] text-muted-foreground/70">({stringXrefList.length})</span>
                </div>
                {stringXrefList.length === 0 ? (
                  <div className="flex items-center justify-center flex-1 text-xs text-muted-foreground">{t("hermes_no_refs")}</div>
                ) : (
                  <div className="flex-1 overflow-auto">
                    {stringXrefList.map((ref, i) => (
                      <button type="button" key={i} className="block w-full text-left px-3 py-1 text-xs font-mono border-b border-border/40 hover:bg-accent/50 cursor-pointer focus-visible:outline-2 focus-visible:outline-ring" onClick={() => {
                        // Try to navigate to the function that references this string
                        if (ref.fcnName) {
                          const fn = functions.find((f) => f.name === ref.fcnName);
                          if (fn) {
                            const pseudo: DexMethod = { addr: fn.addr, index: 0, flags: "", signature: fn.name, name: fn.name };
                            const pseudoCls: DexClass = { addr: fn.addr, name: fn.name, superclass: "", size: fn.size, methods: [pseudo], fields: [] };
                            selectMethod(pseudoCls, pseudo);
                          }
                        }
                      }}>
                        <span className="text-muted-foreground">{ref.addr}</span>
                        {ref.fcnName && <span className="ml-2">{ref.fcnName}</span>}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ) : methodXrefList.length > 0 ? (
              <div className="h-full flex flex-col">
                <div className="flex items-center gap-1.5 px-3 py-1.5 shrink-0 border-b bg-muted/50">
                  <span className="text-[11px] font-semibold tracking-wide uppercase text-muted-foreground">{t("r2_xrefs")}</span>
                  <span className="text-[10px] text-muted-foreground/70">({methodXrefList.length})</span>
                </div>
                <div className="flex-1 overflow-auto">
                  {methodXrefList.map((ref, i) => (
                    <button type="button" key={i} className="block w-full text-left px-3 py-1 text-xs font-mono border-b border-border/40 hover:bg-accent/50 cursor-pointer focus-visible:outline-2 focus-visible:outline-ring" onClick={() => {
                      if (ref.fcnName) {
                        const fn = functions.find((f) => f.name === ref.fcnName);
                        if (fn) {
                          const pseudo: DexMethod = { addr: fn.addr, index: 0, flags: "", signature: fn.name, name: fn.name };
                          const pseudoCls: DexClass = { addr: fn.addr, name: fn.name, superclass: "", size: fn.size, methods: [pseudo], fields: [] };
                          selectMethod(pseudoCls, pseudo);
                        }
                      }
                    }}>
                      <span className="text-muted-foreground">{ref.addr}</span>
                      {ref.fcnName && <span className="ml-2">{ref.fcnName}</span>}
                    </button>
                  ))}
                </div>
              </div>
            ) : (
              <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
                {t("hermes_select_refs")}
              </div>
            )}
          </ResizablePanel>
          </ResizablePanelGroup>
        </ResizablePanel>

        <ResizableHandle />

        {/* Right: code view */}
        <ResizablePanel id="r2-code" defaultSize="65%" minSize="30%">
          <div className="h-full flex flex-col">
            {/* View mode tabs */}
            {selectedMethod && (
              <div className="flex items-center border-b shrink-0">
                <Tabs value={viewMode} onValueChange={(v) => changeViewMode(v as ViewMode)}>
                  <TabsList variant="line">
                    <TabsTrigger value="disassembly">{t("hermes_disassembly")}</TabsTrigger>
                    <TabsTrigger value="graph">Graph</TabsTrigger>
                    <TabsTrigger value="split">{t("r2_split")}</TabsTrigger>
                    {(cpu || isDex) && <TabsTrigger value="decompiler">Decompile</TabsTrigger>}
                  </TabsList>
                </Tabs>
                <div className="flex items-center gap-0.5 ml-auto px-2">
                  <Button
                    variant="ghost"
                    size="sm"
                    className={`h-6 w-6 p-0 ${showBytes ? "text-primary" : ""}`}
                    onClick={() => {
                      setShowBytes(!showBytes);
                      if (selectedMethod) loadDisassembly(selectedMethod);
                    }}
                    title={t("r2_toggle_bytes")}
                  >
                    <Binary className="h-3.5 w-3.5" />
                  </Button>
                  <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setRenameOpen(true)} title={t("r2_rename")}>
                    <Pencil className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </div>
            )}

            {/* Content */}
            <div className="flex-1 overflow-hidden">
              {selectedString ? (
                <div className="h-full flex flex-col">
                  <div className="p-3 border-b">
                    <pre className="font-mono text-xs whitespace-pre-wrap break-all">
                      {selectedString.value || <span className="text-muted-foreground italic">(empty)</span>}
                    </pre>
                  </div>
                  <div className="px-3 py-1 text-[10px] text-muted-foreground border-b">
                    {t("hermes_referenced_by")} ({stringXrefList.length})
                  </div>
                  <div className="flex-1 overflow-auto">
                    {stringXrefList.map((ref, i) => (
                      <div key={i} className="px-3 py-1 text-xs font-mono border-b border-border/40 hover:bg-accent/50">
                        <span className="text-muted-foreground">{ref.addr}</span>
                        {ref.fcnName && <span className="ml-2">{ref.fcnName}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              ) : viewMode === "decompiler" && selectedMethod ? (
                <Decompiler load={load} engine={isDex ? "DDC" : "Kuna"} />
              ) : viewMode === "split" && selectedMethod ? (
                <ResizablePanelGroup orientation="horizontal" autoSaveId="r2-split">
                  <ResizablePanel id="r2-split-asm" defaultSize="50%" minSize="20%">
                    {codeLoading ? (
                      <div className="flex items-center justify-center h-full text-muted-foreground">
                        <Loader2 className="h-4 w-4 animate-spin mr-2" />Loading...
                      </div>
                    ) : codeHtml ? (
                      <div className="disassembly-view h-full overflow-auto p-3 font-mono text-xs whitespace-pre" dangerouslySetInnerHTML={{ __html: codeHtml }} />
                    ) : (
                      <div className="flex items-center justify-center h-full text-xs text-muted-foreground">{t("r2_no_disasm")}</div>
                    )}
                  </ResizablePanel>
                  <ResizableHandle />
                  <ResizablePanel id="r2-split-cfg" defaultSize="50%" minSize="20%">
                    {cfgLoading ? (
                      <div className="flex items-center justify-center h-full text-muted-foreground">
                        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_loading_graph")}
                      </div>
                    ) : cfgData ? (
                      <CFGView nodes={cfgData.nodes} edges={cfgData.edges} fnName={selectedMethod?.name} />
                    ) : (
                      <div className="flex items-center justify-center h-full text-xs text-muted-foreground">{t("r2_no_graph")}</div>
                    )}
                  </ResizablePanel>
                </ResizablePanelGroup>
              ) : viewMode === "graph" && selectedMethod ? (
                cfgLoading ? (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_loading_graph")}
                  </div>
                ) : cfgData ? (
                  <CFGView nodes={cfgData.nodes} edges={cfgData.edges} fnName={selectedMethod?.name} />
                ) : (
                  <div className="flex items-center justify-center h-full text-sm text-muted-foreground">{t("r2_no_graph")}</div>
                )
              ) : codeLoading ? (
                <div className="flex items-center justify-center h-full text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />Loading...
                </div>
              ) : codeHtml ? (
                <div className="disassembly-view h-full overflow-auto p-3 font-mono text-xs whitespace-pre" dangerouslySetInnerHTML={{ __html: codeHtml }} />
              ) : (
                <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                  {t("hermes_click_function")}
                </div>
              )}
            </div>
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>
      <DisassemblyMinimap
        cmd={async (c) => cmd(c)}
        isReady
        currentAddr={selectedMethod?.addr}
        functions={functions}
        onSeek={(addr, fnName) => {
          if (fnName) {
            const fn = functions.find((f) => f.name === fnName);
            if (fn) {
              const pseudo: DexMethod = { addr: fn.addr, index: 0, flags: "", signature: fn.name, name: fn.name };
              const pseudoCls: DexClass = { addr: fn.addr, name: fn.name, superclass: "", size: fn.size, methods: [pseudo], fields: [] };
              selectMethod(pseudoCls, pseudo);
              return;
            }
          }
          // No exact function match — just select by addr
          const fn = functions.find((f) => f.addr === addr);
          if (fn) {
            const pseudo: DexMethod = { addr: fn.addr, index: 0, flags: "", signature: fn.name, name: fn.name };
            const pseudoCls: DexClass = { addr: fn.addr, name: fn.name, superclass: "", size: fn.size, methods: [pseudo], fields: [] };
            selectMethod(pseudoCls, pseudo);
          }
        }}
      />
      </div>

      {selectedMethod && (
        <>
          <RenameDialog
            open={renameOpen}
            onOpenChange={setRenameOpen}
            currentName={selectedMethod.name}
            address={selectedMethod.addr}
            onRename={async (newName) => {
              try {
                await cmd(`afn ${newName} @ ${selectedMethod.addr}`);
                loadDisassembly(selectedMethod);
              } catch {}
            }}
          />
        </>
      )}
    </div>
  );
}

function ClassTree({ classes, expanded, onToggle, selectedClass, selectedMethod, onSelectClass, onSelectMethod }: {
  classes: DexClass[];
  expanded: Set<string>;
  onToggle: (name: string) => void;
  selectedClass: DexClass | null;
  selectedMethod: DexMethod | null;
  onSelectClass: (cls: DexClass) => void;
  onSelectMethod: (cls: DexClass, method: DexMethod) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);

  // Flatten tree for virtualization
  const flat = useMemo(() => {
    const items: { kind: "class"; cls: DexClass }[] | { kind: "method"; cls: DexClass; method: DexMethod }[] = [];
    for (const cls of classes) {
      (items as any[]).push({ kind: "class", cls });
      if (expanded.has(cls.name)) {
        for (const m of cls.methods) {
          (items as any[]).push({ kind: "method", cls, method: m });
        }
      }
    }
    return items as Array<{ kind: "class"; cls: DexClass } | { kind: "method"; cls: DexClass; method: DexMethod }>;
  }, [classes, expanded]);

  const virtualizer = useVirtualizer({
    count: flat.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 20,
  });

  return (
    <div ref={parentRef} className="flex-1 overflow-auto">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative", width: "100%" }}>
        {virtualizer.getVirtualItems().map((vRow) => {
          const item = flat[vRow.index];
          if (item.kind === "class") {
            const isExp = expanded.has(item.cls.name);
            const isSel = selectedClass?.name === item.cls.name && !selectedMethod;
            return (
              <div
                key={`c-${item.cls.name}`}
                role="button" tabIndex={0} onKeyDown={activate}
                className={`absolute top-0 left-0 w-full h-7 px-3 flex items-center gap-1 cursor-pointer border-b border-border/50 transition-colors focus-visible:outline-2 focus-visible:outline-ring ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
                style={{ transform: `translateY(${vRow.start}px)` }}
                onClick={() => { onToggle(item.cls.name); onSelectClass(item.cls); }}
              >
                {isExp ? <ChevronDown className="h-3 w-3 shrink-0" /> : <ChevronExpand className="h-3 w-3 shrink-0" />}
                <span className="font-mono text-xs truncate">{item.cls.name}</span>
                <Badge variant="outline" className="text-[8px] px-1 py-0 ml-auto shrink-0">{item.cls.methods.length}</Badge>
              </div>
            );
          }
          const isSel = selectedMethod?.addr === item.method.addr;
          return (
            <div
              key={`m-${item.method.addr}`}
                role="button" tabIndex={0} onKeyDown={activate}
              className={`absolute top-0 left-0 w-full h-7 pl-8 pr-3 flex items-center cursor-pointer border-b border-border/50 transition-colors focus-visible:outline-2 focus-visible:outline-ring ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
              style={{ transform: `translateY(${vRow.start}px)` }}
              onClick={() => onSelectMethod(item.cls, item.method)}
            >
              <span className="font-mono text-xs truncate text-muted-foreground">{item.method.flags}</span>
              <span className="font-mono text-xs truncate ml-1">{item.method.name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StringList({ strings, selectedVaddr, onSelect }: {
  strings: DexString[];
  selectedVaddr: number | null;
  onSelect: (str: DexString) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: strings.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 20,
  });

  return (
    <div ref={parentRef} className="flex-1 overflow-auto">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative", width: "100%" }}>
        {virtualizer.getVirtualItems().map((vRow) => {
          const str = strings[vRow.index];
          const isSel = str.vaddr === selectedVaddr;
          return (
            <div
              key={str.vaddr}
                role="button" tabIndex={0} onKeyDown={activate}
              className={`absolute top-0 left-0 w-full h-7 px-3 flex items-center cursor-pointer border-b border-border/50 transition-colors focus-visible:outline-2 focus-visible:outline-ring ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
              style={{ transform: `translateY(${vRow.start}px)` }}
              onClick={() => onSelect(str)}
            >
              <span className="font-mono text-xs truncate">{str.value || <span className="text-muted-foreground italic">(empty)</span>}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FuncList({ functions, selectedAddr, onSelect }: {
  functions: R2Function[];
  selectedAddr: string | null;
  onSelect: (fn: R2Function) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: functions.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 20,
  });

  return (
    <div ref={parentRef} className="flex-1 overflow-auto">
      <div style={{ height: virtualizer.getTotalSize(), position: "relative", width: "100%" }}>
        {virtualizer.getVirtualItems().map((vRow) => {
          const fn = functions[vRow.index];
          const isSel = fn.addr === selectedAddr;
          return (
            <div
              key={fn.addr}
                role="button" tabIndex={0} onKeyDown={activate}
              className={`absolute top-0 left-0 w-full h-9 px-3 py-1 flex flex-col justify-center cursor-pointer border-b border-border/50 transition-colors focus-visible:outline-2 focus-visible:outline-ring ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
              style={{ transform: `translateY(${vRow.start}px)` }}
              onClick={() => onSelect(fn)}
            >
              <div className="font-mono text-xs truncate" title={fn.name}>{fn.name}</div>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
                <span className="font-mono">{fn.addr}</span>
                <span>{fn.size}B</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

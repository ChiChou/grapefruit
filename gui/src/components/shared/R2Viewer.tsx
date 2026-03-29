/**
 * Radare2 binary viewer: classes/functions, strings, disassembly, CFG, AI decompile.
 * Supports DEX, native binaries, and other formats radare2 can analyze.
 */
import { useCallback, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Loader2,
  Search,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  ChevronDown,
  ChevronRight as ChevronExpand,
} from "lucide-react";
import Editor from "@monaco-editor/react";
import { useVirtualizer } from "@tanstack/react-virtual";
import * as strip from "@/lib/strip";
import { Parser } from "@/lib/codefence";

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
import { useTheme } from "@/components/providers/ThemeProvider";
import { CFGView, type CFGNode, type CFGEdge } from "@/components/shared/CFGView";
import type { DexClass, DexMethod, DexString, StringXref, R2Function } from "@/lib/r2";

import "../tabs/DisassemblyTab.css";

export interface R2ViewerProps {
  binType: string;
  arch: string;
  classes: DexClass[];
  functions: R2Function[];
  strings: DexString[];
  cmd: (command: string, output?: "plain" | "html") => Promise<string>;
  disassemble: (address: string, output?: "plain" | "html") => Promise<string>;
  cfg: (address: string) => Promise<{ nodes: CFGNode[]; edges: CFGEdge[] } | null>;
  xrefs: (vaddr: number) => Promise<StringXref[]>;
  funcXrefs: (address: string) => Promise<StringXref[]>;
}

type LeftTab = "classes" | "functions" | "strings";

type ViewMode = "disassembly" | "graph" | "decompiler" | "ai-decompile";

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function htmlToPlain(html: string): string {
  return html.replace(/<[^>]*>/g, "");
}

export function R2Viewer({
  binType,
  arch,
  classes,
  functions,
  strings,
  cmd,
  disassemble,
  cfg,
  xrefs,
  funcXrefs,
}: R2ViewerProps) {
  const { t } = useTranslation();
  const { theme } = useTheme();

  const [leftTab, setLeftTab] = useState<LeftTab>("functions");
  const [classSearch, setClassSearch] = useState("");
  const [funcSearch, setFuncSearch] = useState("");
  const [strSearch, setStrSearch] = useState("");

  const [selectedClass, setSelectedClass] = useState<DexClass | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<DexMethod | null>(null);
  const [selectedString, setSelectedString] = useState<DexString | null>(null);
  const [expandedClasses, setExpandedClasses] = useState<Set<string>>(new Set());

  const [viewMode, setViewMode] = useState<ViewMode>("disassembly");
  const [codeHtml, setCodeHtml] = useState("");
  const [codeLoading, setCodeLoading] = useState(false);

  const [cfgData, setCfgData] = useState<{ nodes: CFGNode[]; edges: CFGEdge[] } | null>(null);
  const [cfgLoading, setCfgLoading] = useState(false);

  const [pdcContent, setPdcContent] = useState("");
  const [pdcLoading, setPdcLoading] = useState(false);

  const [aiContent, setAiContent] = useState("");
  const [aiLang, setAiLang] = useState("cpp");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const aiCache = useRef<Map<string, string>>(new Map());
  const aiAbort = useRef<AbortController | null>(null);

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
        const html = await disassemble(method.addr, "html");
        setCodeHtml(html);
      } catch {
        setCodeHtml("<pre>; Failed to disassemble</pre>");
      } finally {
        setCodeLoading(false);
      }
    },
    [disassemble],
  );

  const loadPdc = useCallback(
    async (method: DexMethod) => {
      setPdcLoading(true);
      try {
        const output = await cmd(`e scr.color=0; s ${method.addr}; af; pdc`);
        setPdcContent(output);
      } catch {
        setPdcContent("// Decompiler failed");
      } finally {
        setPdcLoading(false);
      }
    },
    [cmd],
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

  const loadAi = useCallback(
    async (cls: DexClass, method: DexMethod) => {
      const cacheKey = `${cls.name}.${method.name}@${method.addr}`;
      const cached = aiCache.current.get(cacheKey);
      if (cached) {
        try {
          const { lang: l, code } = JSON.parse(cached);
          setAiLang(l || "cpp");
          setAiContent(code);
        } catch {
          setAiContent(cached);
        }
        setAiError(null);
        return;
      }

      aiAbort.current?.abort();
      const ac = new AbortController();
      aiAbort.current = ac;

      setAiLoading(true);
      setAiError(null);
      setAiContent("");

      try {
        const raw = await disassemble(method.addr, "html");
        const plain = strip.r2(htmlToPlain(raw));

        const prompt = [
          "Decompile the following disassembly into clean, idiomatic source code.",
          "Infer the language from context (binary type, arch, symbol names).",
          "Reply with a single fenced code block: ```lang\\n...code...\\n```",
          "No comments, no explanations, no boilerplate — only the reconstructed function body.",
          "",
          `Binary: ${binType || "unknown"}, ${arch || "unknown"}`,
          `Function: ${cls.name}.${method.name}`,
          "",
          plain,
        ].join("\n");

        const res = await fetch("/api/llm/stream", {
          method: "POST",
          body: prompt,
          signal: ac.signal,
        });
        if (!res.ok) throw new Error(await res.text());

        const reader = res.body!.getReader();
        const decoder = new TextDecoder();
        const parser = new Parser();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          parser.push(decoder.decode(value, { stream: true }));
          if (parser.started && parser.lang) setAiLang(parser.lang);
          setAiContent(parser.code);
        }
        aiCache.current.set(cacheKey, JSON.stringify({ lang: parser.lang, code: parser.code }));
      } catch (e) {
        if (ac.signal.aborted) return;
        setAiError(e instanceof Error ? e.message : "AI decompilation failed");
      } finally {
        setAiLoading(false);
      }
    },
    [disassemble, binType, arch],
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

      if (viewMode === "ai-decompile") {
        loadAi(cls, method);
      } else if (viewMode === "graph") {
        loadDisassembly(method);
        loadCfg(method);
      } else if (viewMode === "decompiler") {
        loadPdc(method);
      } else {
        loadDisassembly(method);
      }
    },
    [viewMode, loadDisassembly, loadCfg, loadPdc, loadAi, funcXrefs],
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

  const changeViewMode = useCallback(
    (mode: ViewMode) => {
      setViewMode(mode);
      if (!selectedMethod || !selectedClass) return;
      if (mode === "ai-decompile") loadAi(selectedClass, selectedMethod);
      else if (mode === "graph") loadCfg(selectedMethod);
      else if (mode === "decompiler") loadPdc(selectedMethod);
      else loadDisassembly(selectedMethod);
    },
    [selectedMethod, selectedClass, loadDisassembly, loadCfg, loadPdc, loadAi],
  );

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

      {/* Split view */}
      <ResizablePanelGroup orientation="horizontal" autoSaveId="r2-analysis" className="flex-1">
        {/* Left: classes + strings */}
        <ResizablePanel id="r2-left" defaultSize="35%" minSize="20%">
          <ResizablePanelGroup orientation="vertical" autoSaveId="r2-left-v">
          <ResizablePanel id="r2-browse" defaultSize="70%" minSize="30%">
          <Tabs value={leftTab} onValueChange={(v) => setLeftTab(v as LeftTab)} className="h-full flex flex-col">
            <TabsList variant="line" className="shrink-0">
              <TabsTrigger value="functions">{t("hermes_functions")} ({functions.length})</TabsTrigger>
              <TabsTrigger value="classes">Classes ({classes.length})</TabsTrigger>
              <TabsTrigger value="strings">{t("hermes_strings")} ({strings.length})</TabsTrigger>
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
                <div className="px-3 py-1 text-[10px] text-muted-foreground shrink-0 border-b">
                  {t("hermes_referenced_by")} ({stringXrefList.length})
                </div>
                {stringXrefList.length === 0 ? (
                  <div className="flex items-center justify-center flex-1 text-xs text-muted-foreground">{t("hermes_no_refs")}</div>
                ) : (
                  <div className="flex-1 overflow-auto">
                    {stringXrefList.map((ref, i) => (
                      <div key={i} className="px-3 py-1 text-xs font-mono border-b border-border/40 hover:bg-accent/50 cursor-pointer" onClick={() => {
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
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ) : methodXrefList.length > 0 ? (
              <div className="h-full flex flex-col">
                <div className="px-3 py-1 text-[10px] text-muted-foreground shrink-0 border-b">
                  {t("hermes_called_by")} ({methodXrefList.length})
                </div>
                <div className="flex-1 overflow-auto">
                  {methodXrefList.map((ref, i) => (
                    <div key={i} className="px-3 py-1 text-xs font-mono border-b border-border/40 hover:bg-accent/50 cursor-pointer" onClick={() => {
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
                    </div>
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
                    <TabsTrigger value="decompiler">{t("hermes_pseudocode")}</TabsTrigger>
                    <TabsTrigger value="ai-decompile">{t("hermes_ai_decompile")}</TabsTrigger>
                  </TabsList>
                </Tabs>
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
              ) : viewMode === "ai-decompile" && selectedMethod ? (
                <AiView content={aiContent} isLoading={aiLoading} error={aiError} theme={theme} lang={aiLang} onRetry={() => selectedClass && loadAi(selectedClass, selectedMethod)} />
              ) : viewMode === "decompiler" && selectedMethod ? (
                pdcLoading ? (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />Loading...
                  </div>
                ) : pdcContent ? (
                  <Editor
                    height="100%" language="c" theme={theme === "dark" ? "vs-dark" : "light"} value={pdcContent}
                    options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12, lineNumbers: "off", scrollBeyondLastLine: false, wordWrap: "off" }}
                  />
                ) : (
                  <div className="flex items-center justify-center h-full text-sm text-muted-foreground">{t("hermes_click_function")}</div>
                )
              ) : viewMode === "graph" && selectedMethod ? (
                cfgLoading ? (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />Loading graph...
                  </div>
                ) : cfgData ? (
                  <CFGView nodes={cfgData.nodes} edges={cfgData.edges} />
                ) : (
                  <div className="flex items-center justify-center h-full text-sm text-muted-foreground">No graph data</div>
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
    </div>
  );
}

function AiView({ content, isLoading, error, theme, lang, onRetry }: {
  content: string; isLoading: boolean; error: string | null; theme: string; lang: string; onRetry: () => void;
}) {
  const { t } = useTranslation();

  if (isLoading && !content) {
    return <div className="flex items-center justify-center h-full text-muted-foreground"><Loader2 className="h-4 w-4 animate-spin mr-2" />{t("hermes_ai_loading")}</div>;
  }
  if (error) {
    return (
      <div className="flex items-center justify-center h-full px-6">
        <div className="flex flex-col items-center gap-3 max-w-md text-center">
          <AlertCircle className="h-8 w-8 text-destructive" />
          <p className="text-sm font-medium">{t("hermes_ai_failed")}</p>
          <p className="text-xs text-muted-foreground break-all">{error}</p>
          <Button variant="outline" size="sm" className="text-xs" onClick={onRetry}>{t("retry")}</Button>
        </div>
      </div>
    );
  }
  if (!content) {
    return <div className="flex items-center justify-center h-full text-sm text-muted-foreground">{t("hermes_ai_select")}</div>;
  }
  return (
    <Editor height="100%" language={lang} theme={theme === "dark" ? "vs-dark" : "light"} value={content}
      options={{ readOnly: true, minimap: { enabled: false }, fontSize: 12, lineNumbers: "on", scrollBeyondLastLine: false, wordWrap: "on" }}
    />
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
                className={`absolute top-0 left-0 w-full h-7 px-3 flex items-center gap-1 cursor-pointer border-b border-border/50 transition-colors ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
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
              className={`absolute top-0 left-0 w-full h-7 pl-8 pr-3 flex items-center cursor-pointer border-b border-border/50 transition-colors ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
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
              className={`absolute top-0 left-0 w-full h-7 px-3 flex items-center cursor-pointer border-b border-border/50 transition-colors ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
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
              className={`absolute top-0 left-0 w-full h-9 px-3 py-1 flex flex-col justify-center cursor-pointer border-b border-border/50 transition-colors ${isSel ? "bg-primary/10 dark:bg-primary/20" : "hover:bg-accent/50"}`}
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

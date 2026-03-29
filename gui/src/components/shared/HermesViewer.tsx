import { useCallback, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import {
  Loader2,
  Search,
  AlertCircle,
  ChevronLeft,
  ChevronRight,
  Copy,
  Download,
  Check,
  ChevronDown,
} from "lucide-react";
import Editor from "@monaco-editor/react";
import { useVirtualizer } from "@tanstack/react-virtual";
import { parse, resolve, buildLlmContext } from "@/lib/hermes-asm";
import { HermesDisasm } from "./HermesDisasm";

import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import {
  DropdownMenu,
  DropdownMenuTrigger,
  DropdownMenuContent,
  DropdownMenuItem,
} from "@/components/ui/dropdown-menu";
import { useTheme } from "@/components/providers/ThemeProvider";
import type {
  AnalysisData,
  HBCFunction,
  HBCString,
  HBCXrefs,
} from "@/lib/use-hbc";

export interface HermesViewerProps {
  data: AnalysisData;
  xrefs: HBCXrefs | null;
  filename: string;
  buffer: ArrayBuffer | null;
  disassemble: (funcId?: number | null) => Promise<string | null>;
  decompile: (funcId?: number | null, opts?: { offsets?: boolean }) => Promise<string | null>;
}

type ViewMode = "disassembly" | "pseudocode" | "ai-decompile";
type LeftTab = "functions" | "strings";

function formatHex(n: number): string {
  return "0x" + n.toString(16);
}

function downloadBlob(content: string, filename: string) {
  const blob = new Blob([content], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

export function HermesViewer({
  data,
  xrefs,
  filename,
  buffer,
  disassemble,
  decompile,
}: HermesViewerProps) {
  const { t } = useTranslation();
  const { theme } = useTheme();

  const [leftTab, setLeftTab] = useState<LeftTab>(
    () => (localStorage.getItem("hermes-left-tab") as LeftTab) || "functions",
  );
  const [funcSearch, setFuncSearch] = useState("");
  const [selectedFuncId, setSelectedFuncId] = useState<number | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>(
    () =>
      (localStorage.getItem("hermes-view-mode") as ViewMode) || "disassembly",
  );

  const [codeContent, setCodeContent] = useState("");
  const [codeLoading, setCodeLoading] = useState(false);
  const [showAddresses, setShowAddresses] = useState(
    () => localStorage.getItem("hermes-show-addr") !== "false",
  );
  const [copied, setCopied] = useState(false);

  const [strSearch, setStrSearch] = useState("");
  const [strKindFilter, setStrKindFilter] = useState("all");
  const [selectedString, setSelectedString] = useState<HBCString | null>(null);

  const [aiContent, setAiContent] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const aiCache = useRef<Map<number | null, string>>(new Map());
  const aiAbort = useRef<AbortController | null>(null);

  // Navigation history: stores { funcId, label }
  const historyRef = useRef<{ funcId: number; name: string }[]>([]);
  const historyIdx = useRef(-1);
  const navigatingRef = useRef(false);
  // Force re-render when history changes (refs don't trigger renders)
  const [, setHistoryTick] = useState(0);

  const fetchCode = useCallback(
    async (funcId: number | null, mode: ViewMode) => {
      setCodeLoading(true);
      try {
        let source: string | null;
        if (mode === "disassembly") {
          source = await disassemble(funcId);
        } else {
          source = await decompile(funcId);
        }
        if (source == null) {
          setCodeContent(
            mode === "disassembly"
              ? "; Failed to disassemble"
              : "// Failed to decompile",
          );
          return;
        }

        if (mode === "disassembly" && funcId !== null) {
          const func = data.functions.find((f) => f.id === funcId);
          if (func) {
            const params = Array.from(
              { length: func.paramCount },
              (_, i) => `a${i}`,
            ).join(", ");
            const header = `; function ${func.name}(${params})  [#${func.id}, ${func.size} bytes]`;
            source = source.replace(
              /^\s*@\s*offset\s+0x[0-9a-f]+\s*\n+Bytecode listing \(asm\):\s*\n*/,
              header + "\n\n",
            );
          }
        }

        setCodeContent(source);
      } finally {
        setCodeLoading(false);
      }
    },
    [disassemble, decompile, data.functions],
  );

  const stringXrefFuncs = useMemo(() => {
    if (!selectedString || !xrefs) return [];
    const callers = xrefs.strings[String(selectedString.index)];
    if (!callers) return [];
    return callers.map((id) => data.functions[id]).filter(Boolean);
  }, [selectedString, xrefs, data]);

  const funcCallers = useMemo(() => {
    if (selectedFuncId === null || !xrefs) return [];
    const callers = xrefs.functions[String(selectedFuncId)];
    if (!callers) return [];
    return callers.map((id) => data.functions[id]).filter(Boolean);
  }, [selectedFuncId, xrefs, data]);

  const handleStringClick = useCallback((str: HBCString) => {
    setSelectedString(str);
    setSelectedFuncId(null);
  }, []);

  const changeLeftTab = useCallback((tab: LeftTab) => {
    setLeftTab(tab);
    localStorage.setItem("hermes-left-tab", tab);
    if (tab === "functions") setSelectedString(null);
  }, []);

  const loadAiDecompile = useCallback(
    async (funcId: number | null) => {
      const cached = aiCache.current.get(funcId);
      if (cached) {
        setAiContent(cached);
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
        const disasm = (await disassemble(funcId)) ?? "";

        const func =
          funcId !== null ? data.functions.find((f) => f.id === funcId) : null;
        const funcName =
          func?.name ??
          (funcId !== null ? `function #${funcId}` : "global code");
        const paramCount = func?.paramCount;

        const lines = parse(disasm);
        resolve(lines, data.strings, data.functions);
        const prompt = buildLlmContext(
          lines,
          funcName,
          paramCount,
          data.strings,
          data.functions,
        );
        console.log("[hermes] LLM prompt (%d chars):\n%s", prompt.length, prompt);

        const llmRes = await fetch("/api/llm/stream", {
          method: "POST",
          body: prompt,
          signal: ac.signal,
        });
        if (!llmRes.ok) throw new Error(await llmRes.text());

        const reader = llmRes.body!.getReader();
        const decoder = new TextDecoder();
        let accumulated = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          accumulated += decoder.decode(value, { stream: true });
          setAiContent(accumulated);
        }

        aiCache.current.set(funcId, accumulated);
      } catch (e) {
        if (ac.signal.aborted) return;
        setAiError(e instanceof Error ? e.message : "AI decompilation failed");
      } finally {
        setAiLoading(false);
      }
    },
    [disassemble, data.functions, data.strings],
  );

  const changeViewMode = useCallback(
    (mode: ViewMode) => {
      setViewMode(mode);
      localStorage.setItem("hermes-view-mode", mode);
      if (mode === "ai-decompile") {
        loadAiDecompile(selectedFuncId);
      } else {
        fetchCode(selectedFuncId, mode);
      }
    },
    [selectedFuncId, fetchCode, loadAiDecompile],
  );

  const navigateTo = useCallback(
    (funcId: number) => {
      setSelectedFuncId(funcId);
      setSelectedString(null);
      if (viewMode === "ai-decompile") {
        loadAiDecompile(funcId);
      } else {
        fetchCode(funcId, viewMode);
      }
    },
    [viewMode, fetchCode, loadAiDecompile],
  );

  const handleFuncClick = useCallback(
    (funcId: number) => {
      if (!navigatingRef.current) {
        const func = data.functions.find((f) => f.id === funcId);
        const name = func?.name ?? `#${funcId}`;
        historyRef.current = historyRef.current.slice(0, historyIdx.current + 1);
        historyRef.current.push({ funcId, name });
        historyIdx.current = historyRef.current.length - 1;
        setHistoryTick((t) => t + 1);
      }
      navigateTo(funcId);
    },
    [navigateTo, data.functions],
  );

  const canGoBack = historyIdx.current > 0;
  const canGoForward = historyIdx.current < historyRef.current.length - 1;

  const goTo = useCallback(
    (idx: number) => {
      if (idx < 0 || idx >= historyRef.current.length) return;
      historyIdx.current = idx;
      navigatingRef.current = true;
      navigateTo(historyRef.current[idx].funcId);
      navigatingRef.current = false;
      setHistoryTick((t) => t + 1);
    },
    [navigateTo],
  );

  const handleXrefClick = useCallback(
    (func: HBCFunction) => {
      setSelectedString(null);
      setLeftTab("functions");
      localStorage.setItem("hermes-left-tab", "functions");
      handleFuncClick(func.id);
    },
    [handleFuncClick],
  );

  const filteredFunctions = useMemo(() => {
    if (!funcSearch.trim()) return data.functions;
    const q = funcSearch.toLowerCase();
    return data.functions.filter((f) => f.name.toLowerCase().includes(q));
  }, [data, funcSearch]);

  const filteredStrings = useMemo(() => {
    let list = data.strings;
    if (strKindFilter !== "all") {
      list = list.filter((s) => s.kind === strKindFilter);
    }
    if (strSearch.trim()) {
      const q = strSearch.toLowerCase();
      list = list.filter((s) => s.value.toLowerCase().includes(q));
    }
    return list;
  }, [data, strSearch, strKindFilter]);

  const toggleAddresses = useCallback(() => {
    setShowAddresses((v) => {
      localStorage.setItem("hermes-show-addr", String(!v));
      return !v;
    });
  }, []);

  const copyCode = useCallback(() => {
    navigator.clipboard.writeText(codeContent);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  }, [codeContent]);

  const downloadFunc = useCallback(async () => {
    if (selectedFuncId === null) return;
    const src = viewMode === "disassembly"
      ? await disassemble(selectedFuncId)
      : await decompile(selectedFuncId);
    if (!src) return;
    const func = data.functions.find((f) => f.id === selectedFuncId);
    const name = func?.name ?? `func_${selectedFuncId}`;
    const ext = viewMode === "disassembly" ? "asm" : "js";
    downloadBlob(src, `${name}.${ext}`);
  }, [selectedFuncId, viewMode, disassemble, decompile, data.functions]);

  const history = historyRef.current;
  const currentIdx = historyIdx.current;

  return (
    <div className="h-full flex flex-col">
      {/* Navigation bar */}
      <div className="flex items-center gap-1 px-2 border-b shrink-0 h-8">
        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <button
                className="p-1 rounded hover:bg-accent disabled:opacity-30 cursor-pointer disabled:cursor-default"
                disabled={!canGoBack}
              />
            }
          >
            <ChevronLeft className="h-4.5 w-4.5" />
          </DropdownMenuTrigger>
          {history.length > 1 && (
            <DropdownMenuContent>
              {history.slice(0, currentIdx).reverse().map((entry, ri) => {
                const idx = currentIdx - 1 - ri;
                return (
                  <DropdownMenuItem key={idx} onClick={() => goTo(idx)}>
                    <span className="font-mono text-xs truncate">{entry.name}</span>
                  </DropdownMenuItem>
                );
              })}
            </DropdownMenuContent>
          )}
        </DropdownMenu>

        <DropdownMenu>
          <DropdownMenuTrigger
            render={
              <button
                className="p-1 rounded hover:bg-accent disabled:opacity-30 cursor-pointer disabled:cursor-default"
                disabled={!canGoForward}
              />
            }
          >
            <ChevronRight className="h-4.5 w-4.5" />
          </DropdownMenuTrigger>
          {history.length > currentIdx + 1 && (
            <DropdownMenuContent>
              {history.slice(currentIdx + 1).map((entry, ri) => {
                const idx = currentIdx + 1 + ri;
                return (
                  <DropdownMenuItem key={idx} onClick={() => goTo(idx)}>
                    <span className="font-mono text-xs truncate">{entry.name}</span>
                  </DropdownMenuItem>
                );
              })}
            </DropdownMenuContent>
          )}
        </DropdownMenu>

        <div className="flex-1" />

        <Badge variant="secondary" className="text-[10px] shrink-0">
          v{data.info.version}
        </Badge>
        <Badge variant="outline" className="text-[10px] shrink-0">
          {formatSize(data.info.fileLength)}
        </Badge>

        <DropdownMenu>
          <DropdownMenuTrigger
            render={<Button variant="ghost" size="sm" className="h-7 px-2 text-xs" />}
          >
            <Download className="h-3.5 w-3.5 mr-1" />
            {t("hermes_download")}
            <ChevronDown className="h-3 w-3 ml-1 opacity-50" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" className="min-w-0">
            <DropdownMenuItem
              onClick={async () => {
                const src = await decompile(null);
                if (src) {
                  const base = filename.replace(/\.[^.]+$/, "") || "hermes";
                  downloadBlob(src, `${base}.js`);
                }
              }}
            >
              {t("hermes_download_js")}
            </DropdownMenuItem>
            <DropdownMenuItem
              onClick={async () => {
                const src = await disassemble(null);
                if (src) {
                  const base = filename.replace(/\.[^.]+$/, "") || "hermes";
                  downloadBlob(src, `${base}.asm`);
                }
              }}
            >
              {t("hermes_download_asm")}
            </DropdownMenuItem>
            {buffer && (
              <DropdownMenuItem
                onClick={() => {
                  const blob = new Blob([buffer], { type: "application/octet-stream" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = filename || "hermes.hbc";
                  a.click();
                  URL.revokeObjectURL(url);
                }}
              >
                {t("hermes_download_raw")}
              </DropdownMenuItem>
            )}
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      {/* Main split view */}
      <ResizablePanelGroup
        orientation="horizontal"
        autoSaveId="hermes-analysis"
        className="flex-1"
      >
        {/* Left panel: functions/strings + xrefs */}
        <ResizablePanel id="hermes-left" defaultSize="35%" minSize="20%">
          <ResizablePanelGroup orientation="vertical" autoSaveId="hermes-left-v">
            {/* Top: functions / strings */}
            <ResizablePanel id="hermes-browse" defaultSize="70%" minSize="30%">
              <Tabs
                value={leftTab}
                onValueChange={(v) => changeLeftTab(v as LeftTab)}
                className="h-full flex flex-col"
              >
                <TabsList variant="line" className="shrink-0">
                  <TabsTrigger value="functions">
                    {t("hermes_functions")} ({data.info.functionCount})
                  </TabsTrigger>
                  <TabsTrigger value="strings">
                    {t("hermes_strings")} ({data.info.stringCount})
                  </TabsTrigger>
                </TabsList>

                <TabsContent
                  value="functions"
                  className="flex-1 overflow-hidden flex flex-col"
                >
                  <div className="px-2 py-1.5 border-b shrink-0">
                    <div className="relative">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                      <Input
                        placeholder={t("hermes_search_functions")}
                        value={funcSearch}
                        onChange={(e) => setFuncSearch(e.target.value)}
                        className="pl-8 h-7 text-xs"
                      />
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-1 px-0.5">
                      {filteredFunctions.length} / {data.functions.length}
                    </div>
                  </div>
                  <FunctionList
                    functions={filteredFunctions}
                    selectedId={selectedFuncId}
                    onSelect={handleFuncClick}
                  />
                </TabsContent>

                <TabsContent
                  value="strings"
                  className="flex-1 overflow-hidden flex flex-col"
                >
                  <div className="px-2 py-1.5 border-b shrink-0 flex items-center gap-2">
                    <div className="relative flex-1">
                      <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                      <Input
                        placeholder={t("hermes_search_strings")}
                        value={strSearch}
                        onChange={(e) => setStrSearch(e.target.value)}
                        className="pl-8 h-7 text-xs"
                      />
                    </div>
                    <select
                      className="h-7 text-[10px] border rounded px-1.5 bg-background"
                      value={strKindFilter}
                      onChange={(e) => setStrKindFilter(e.target.value)}
                    >
                      <option value="all">{t("hermes_str_all")}</option>
                      <option value="string">{t("hermes_str_string")}</option>
                      <option value="identifier">{t("hermes_str_identifier")}</option>
                      <option value="predefined">{t("hermes_str_predefined")}</option>
                    </select>
                  </div>
                  <div className="text-[10px] text-muted-foreground px-2.5 py-1">
                    {filteredStrings.length} / {data.strings.length}
                  </div>
                  <StringList
                    strings={filteredStrings}
                    selectedIndex={selectedString?.index ?? null}
                    onSelect={handleStringClick}
                  />
                </TabsContent>
              </Tabs>
            </ResizablePanel>

            <ResizableHandle />

            {/* Bottom: xrefs / string detail */}
            <ResizablePanel id="hermes-xrefs" defaultSize="30%" minSize="10%">
              {selectedString ? (
                <div className="h-full flex flex-col">
                  <div className="flex items-center gap-2 px-3 py-1.5 border-b shrink-0">
                    <Badge
                      variant={selectedString.kind === "identifier" ? "secondary" : "outline"}
                      className="text-[10px]"
                    >
                      {selectedString.kind}
                    </Badge>
                    <span className="text-[10px] text-muted-foreground">
                      #{selectedString.index}
                    </span>
                  </div>
                  <div className="overflow-auto p-3 border-b">
                    <pre className="font-mono text-xs whitespace-pre-wrap break-all">
                      {selectedString.value || (
                        <span className="text-muted-foreground italic">(empty)</span>
                      )}
                    </pre>
                  </div>
                  <div className="px-3 py-1 text-[10px] text-muted-foreground shrink-0 border-b">
                    {t("hermes_referenced_by")} {stringXrefFuncs.length > 0 ? `(${stringXrefFuncs.length})` : ""}
                  </div>
                  {stringXrefFuncs.length === 0 ? (
                    <div className="flex items-center justify-center flex-1 text-xs text-muted-foreground">
                      {t("hermes_no_refs")}
                    </div>
                  ) : (
                    <XrefList funcs={stringXrefFuncs} onClick={handleXrefClick} />
                  )}
                </div>
              ) : funcCallers.length > 0 ? (
                <div className="h-full flex flex-col">
                  <div className="px-3 py-1 text-[10px] text-muted-foreground shrink-0 border-b">
                    {t("hermes_called_by")} ({funcCallers.length})
                  </div>
                  <XrefList funcs={funcCallers} onClick={handleXrefClick} />
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

        {/* Right panel: code view */}
        <ResizablePanel id="hermes-code" defaultSize="65%" minSize="30%">
          <div className="h-full flex flex-col">
            {/* View mode tabs */}
            <div className="flex items-center border-b shrink-0">
              <Tabs
                value={viewMode}
                onValueChange={(v) => changeViewMode(v as ViewMode)}
              >
                <TabsList variant="line">
                  <TabsTrigger value="disassembly">{t("hermes_disassembly")}</TabsTrigger>
                  <TabsTrigger value="pseudocode">{t("hermes_pseudocode")}</TabsTrigger>
                  <TabsTrigger value="ai-decompile">{t("hermes_ai_decompile")}</TabsTrigger>
                </TabsList>
              </Tabs>
            </div>

            {/* Disassembly sub-toolbar */}
            {viewMode === "disassembly" && codeContent && (
              <div className="flex items-center gap-3 px-3 py-1 border-b shrink-0">
                <label className="flex items-center gap-1.5 text-[10px] text-muted-foreground cursor-pointer select-none">
                  <Switch
                    size="sm"
                    checked={showAddresses}
                    onCheckedChange={toggleAddresses}
                  />
                  {t("hermes_show_address")}
                </label>
                <div className="ml-auto flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0"
                    onClick={copyCode}
                    title={t("hermes_copy")}
                  >
                    {copied ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-6 w-6 p-0"
                    onClick={downloadFunc}
                    title={t("hermes_download_func")}
                    disabled={selectedFuncId === null}
                  >
                    <Download className="h-3 w-3" />
                  </Button>
                </div>
              </div>
            )}

            {/* Code view */}
            <div className="flex-1 overflow-hidden">
              {viewMode === "ai-decompile" ? (
                <AiDecompileView
                  content={aiContent}
                  isLoading={aiLoading}
                  error={aiError}
                  theme={theme}
                  onRetry={() => loadAiDecompile(selectedFuncId)}
                />
              ) : codeLoading ? (
                <div className="flex items-center justify-center h-full text-muted-foreground">
                  <Loader2 className="h-4 w-4 animate-spin mr-2" />
                  Loading...
                </div>
              ) : !codeContent ? (
                <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                  {t("hermes_click_function")}
                </div>
              ) : viewMode === "disassembly" ? (
                <HermesDisasm
                  raw={codeContent}
                  strings={data.strings}
                  functions={data.functions}
                  showAddresses={showAddresses}
                  onFuncClick={handleFuncClick}
                />
              ) : (
                <Editor
                  height="100%"
                  language="javascript"
                  theme={theme === "dark" ? "vs-dark" : "light"}
                  value={codeContent}
                  options={{
                    readOnly: true,
                    minimap: { enabled: false },
                    fontSize: 12,
                    fontFamily:
                      "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
                    lineNumbers: "off",
                    scrollBeyondLastLine: false,
                    wordWrap: "off",
                    renderLineHighlight: "line",
                    smoothScrolling: true,
                    cursorBlinking: "smooth",
                  }}
                />
              )}
            </div>
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>
    </div>
  );
}

function XrefList({
  funcs,
  onClick,
}: {
  funcs: HBCFunction[];
  onClick: (func: HBCFunction) => void;
}) {
  return (
    <div className="flex-1 overflow-auto">
      {funcs.map((func) => (
        <button
          key={func.id}
          className="w-full text-left px-3 py-1.5 hover:bg-accent transition-colors cursor-pointer group border-b border-border/40"
          onClick={() => onClick(func)}
        >
          <div className="flex items-center gap-2 min-w-0">
            <span className="text-[10px] text-muted-foreground font-mono shrink-0 tabular-nums">
              #{func.id}
            </span>
            <span className="font-mono text-xs truncate group-hover:text-accent-foreground">
              {func.name}
            </span>
            <span className="text-[10px] text-muted-foreground font-mono ml-auto shrink-0">
              {formatHex(func.offset)}
            </span>
          </div>
        </button>
      ))}
    </div>
  );
}

function AiDecompileView({
  content,
  isLoading,
  error,
  theme,
  onRetry,
}: {
  content: string;
  isLoading: boolean;
  error: string | null;
  theme: string;
  onRetry: () => void;
}) {
  const { t } = useTranslation();

  if (isLoading && !content) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("hermes_ai_loading")}
      </div>
    );
  }

  if (error) {
    const isNotConfigured =
      error.includes("LLM not configured") || error.includes("LLM_PROVIDER");
    return (
      <div className="flex items-center justify-center h-full px-6">
        <div className="flex flex-col items-center gap-3 max-w-md text-center">
          <AlertCircle className="h-8 w-8 text-destructive" />
          {isNotConfigured ? (
            <>
              <p className="text-sm font-medium">{t("hermes_llm_not_configured")}</p>
              <p className="text-xs text-muted-foreground">
                {t("hermes_llm_not_configured_desc")}
              </p>
              <pre className="text-[11px] text-left bg-muted rounded-md px-3 py-2 w-full font-mono">
                {`LLM_PROVIDER=anthropic   # or openai, gemini, openrouter\nLLM_API_KEY=sk-...\nLLM_MODEL=claude-sonnet-4-20250514`}
              </pre>
            </>
          ) : (
            <>
              <p className="text-sm font-medium">{t("hermes_ai_failed")}</p>
              <p className="text-xs text-muted-foreground break-all">{error}</p>
              <Button
                variant="outline"
                size="sm"
                className="text-xs"
                onClick={onRetry}
              >
                {t("retry")}
              </Button>
            </>
          )}
        </div>
      </div>
    );
  }

  if (!content) {
    return (
      <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
        {t("hermes_ai_select")}
      </div>
    );
  }

  return (
    <Editor
      height="100%"
      language="javascript"
      theme={theme === "dark" ? "vs-dark" : "light"}
      value={content}
      options={{
        readOnly: true,
        minimap: { enabled: false },
        fontSize: 12,
        fontFamily:
          "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
        lineNumbers: "on",
        scrollBeyondLastLine: false,
        wordWrap: "on",
      }}
    />
  );
}

function FunctionList({
  functions,
  selectedId,
  onSelect,
}: {
  functions: HBCFunction[];
  selectedId: number | null;
  onSelect: (id: number) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: functions.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 36,
    overscan: 20,
  });

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
      e.preventDefault();
      const idx =
        selectedId !== null
          ? functions.findIndex((f) => f.id === selectedId)
          : -1;
      const next =
        e.key === "ArrowDown"
          ? Math.min(idx + 1, functions.length - 1)
          : Math.max(idx - 1, 0);
      if (next >= 0 && next < functions.length) {
        onSelect(functions[next].id);
        virtualizer.scrollToIndex(next, { align: "auto" });
      }
    },
    [functions, selectedId, onSelect, virtualizer],
  );

  return (
    <div
      ref={parentRef}
      className="flex-1 overflow-auto outline-none"
      tabIndex={0}
      onKeyDown={handleKeyDown}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const func = functions[virtualRow.index];
          const isSelected = func.id === selectedId;
          return (
            <div
              key={func.id}
              className={`absolute top-0 left-0 w-full h-9 px-3 py-1 flex flex-col justify-center cursor-pointer border-b border-border/50 transition-colors ${
                isSelected
                  ? "bg-primary/10 text-foreground dark:bg-primary/20"
                  : "hover:bg-accent/50"
              }`}
              style={{
                transform: `translateY(${virtualRow.start}px)`,
              }}
              onClick={() => onSelect(func.id)}
            >
              <div className="font-mono text-xs truncate leading-tight" title={func.name}>
                {func.name || <span className="text-muted-foreground italic">anonymous</span>}
              </div>
              <div className="flex items-center gap-2 text-[10px] text-muted-foreground leading-tight">
                <span className="font-mono">{formatHex(func.offset)}</span>
                <span>{func.size}B</span>
                <span>{func.paramCount}p</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function StringList({
  strings,
  selectedIndex,
  onSelect,
}: {
  strings: HBCString[];
  selectedIndex: number | null;
  onSelect: (str: HBCString) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);

  const virtualizer = useVirtualizer({
    count: strings.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 32,
    overscan: 20,
  });

  const handleKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key !== "ArrowUp" && e.key !== "ArrowDown") return;
      e.preventDefault();
      const idx =
        selectedIndex !== null
          ? strings.findIndex((s) => s.index === selectedIndex)
          : -1;
      const next =
        e.key === "ArrowDown"
          ? Math.min(idx + 1, strings.length - 1)
          : Math.max(idx - 1, 0);
      if (next >= 0 && next < strings.length) {
        onSelect(strings[next]);
        virtualizer.scrollToIndex(next, { align: "auto" });
      }
    },
    [strings, selectedIndex, onSelect, virtualizer],
  );

  return (
    <div
      ref={parentRef}
      className="flex-1 overflow-auto outline-none"
      tabIndex={0}
      onKeyDown={handleKeyDown}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const str = strings[virtualRow.index];
          const isSelected = str.index === selectedIndex;
          return (
            <div
              key={str.index}
              className={`absolute top-0 left-0 w-full h-8 px-3 py-1 flex items-center cursor-pointer border-b border-border/50 transition-colors ${
                isSelected
                  ? "bg-primary/10 text-foreground dark:bg-primary/20"
                  : "hover:bg-accent/50"
              }`}
              style={{
                transform: `translateY(${virtualRow.start}px)`,
              }}
              onClick={() => onSelect(str)}
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="font-mono text-xs truncate" title={str.value}>
                  {str.value || (
                    <span className="text-muted-foreground italic">
                      (empty)
                    </span>
                  )}
                </span>
                <Badge
                  variant={str.kind === "identifier" ? "secondary" : "outline"}
                  className="text-[8px] px-1 py-0 ml-auto shrink-0"
                >
                  {str.kind}
                </Badge>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

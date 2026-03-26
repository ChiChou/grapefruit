import { useCallback, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import {
  Loader2,
  Search,
  ChevronRight,
  ChevronDown,
  AlertCircle,
} from "lucide-react";
import Editor from "@monaco-editor/react";
import { useVirtualizer } from "@tanstack/react-virtual";

import {
  useDexR2Session,
  type DexClass,
  type DexMethod,
  type DexString,
  type StringXref,
} from "@/lib/use-dex-r2";
import * as strip from "@/lib/strip";
import {
  CFGView,
  type CFGNode,
  type CFGEdge,
} from "@/components/shared/CFGView";

import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { useSession } from "@/context/SessionContext";
import { useTheme } from "@/components/providers/ThemeProvider";

function escapeHtml(s: string): string {
  return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function htmlToPlain(html: string): string {
  return html.replace(/<[^>]*>/g, "");
}

export interface DexViewerParams {
  path?: string;
  apk?: string;
  entry?: string;
}

type LeftTab = "classes" | "strings";
type ViewMode = "disassembly" | "graph" | "decompile";

const editorOpts = {
  readOnly: true,
  minimap: { enabled: false },
  fontSize: 12,
  fontFamily:
    "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
  lineNumbers: "off" as const,
  scrollBeyondLastLine: false,
  wordWrap: "off" as const,
  renderLineHighlight: "line" as const,
  smoothScrolling: true,
  cursorBlinking: "smooth" as const,
};

export function DexViewerTab({ params }: IDockviewPanelProps<DexViewerParams>) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { device, pid } = useSession();

  const {
    classes,
    strings,
    isLoading,
    error,
    isReady,
    disassembleAt,
    getCFGAt,
    findStringXrefs,
  } = useDexR2Session({
    deviceId: device,
    pid,
    path: params?.path,
    apk: params?.apk,
    entry: params?.entry,
  });

  const totalMethods = useMemo(
    () => classes.reduce((sum, c) => sum + c.methods.length, 0),
    [classes],
  );

  const [expandedClasses, setExpandedClasses] = useState<Set<string>>(
    new Set(),
  );
  const [leftTab, setLeftTab] = useState<LeftTab>(
    () => (localStorage.getItem("dex-left-tab") as LeftTab) || "classes",
  );
  const [classSearch, setClassSearch] = useState("");
  const [strSearch, setStrSearch] = useState("");

  const [selectedClass, setSelectedClass] = useState<DexClass | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<DexMethod | null>(null);
  const [selectedString, setSelectedString] = useState<DexString | null>(null);
  const [codeHtml, setCodeHtml] = useState("");
  const [stringXrefs, setStringXrefs] = useState<StringXref[]>([]);

  const [viewMode, setViewMode] = useState<ViewMode>("disassembly");
  const [cfgData, setCfgData] = useState<{
    nodes: CFGNode[];
    edges: CFGEdge[];
  } | null>(null);
  const [cfgLoading, setCfgLoading] = useState(false);
  const [decompileContent, setDecompileContent] = useState("");
  const [decompileLoading, setDecompileLoading] = useState(false);
  const [decompileError, setDecompileError] = useState<string | null>(null);
  const decompileCache = useRef<Map<string, string>>(new Map());

  const filteredClasses = useMemo(() => {
    if (!classSearch.trim()) return classes;
    const q = classSearch.toLowerCase();
    return classes.filter((c) => c.name.toLowerCase().includes(q));
  }, [classes, classSearch]);

  const filteredStrings = useMemo(() => {
    if (!strSearch.trim()) return strings;
    const q = strSearch.toLowerCase();
    return strings.filter((s) => s.value.toLowerCase().includes(q));
  }, [strings, strSearch]);

  const toggleClass = useCallback((className: string) => {
    setExpandedClasses((prev) => {
      const next = new Set(prev);
      if (next.has(className)) next.delete(className);
      else next.add(className);
      return next;
    });
  }, []);

  const handleClassClick = useCallback(
    (cls: DexClass) => {
      setSelectedClass(cls);
      setSelectedMethod(null);
      setSelectedString(null);
      setViewMode("disassembly");
      toggleClass(cls.name);

      const lines = [
        `; class ${cls.name}`,
        cls.superclass ? `;   extends ${cls.superclass}` : "",
        "",
        ...(cls.fields.length > 0
          ? [
              "; --- Fields ---",
              ...cls.fields.map((f) => `;   [${f.flags}] ${f.signature}`),
              "",
            ]
          : []),
        `; --- Methods (${cls.methods.length}) ---`,
        ...cls.methods.map((m) => `;   [${m.flags}] ${m.signature}`),
      ].filter(Boolean);
      setCodeHtml(escapeHtml(lines.join("\n")));
    },
    [toggleClass],
  );

  const handleMethodClick = useCallback(
    async (cls: DexClass, method: DexMethod) => {
      setSelectedClass(cls);
      setSelectedMethod(method);
      setSelectedString(null);
      setDecompileError(null);
      setDecompileContent("");
      setCfgData(null);
      setViewMode("disassembly");

      setCodeHtml("; Loading disassembly...");
      try {
        const html = await disassembleAt(method.addr, "html");
        setCodeHtml(html || "; (empty disassembly)");
      } catch {
        setCodeHtml("; Failed to disassemble method");
      }
    },
    [disassembleAt],
  );

  const loadCFG = useCallback(async () => {
    if (!selectedMethod || cfgData) return;
    setCfgLoading(true);
    try {
      setCfgData(await getCFGAt(selectedMethod.addr));
    } catch {
      setCfgData(null);
    } finally {
      setCfgLoading(false);
    }
  }, [selectedMethod, cfgData, getCFGAt]);

  const decompileMethod = useCallback(
    async (cls: DexClass, method: DexMethod) => {
      const cacheKey = `${cls.name}.${method.name}@${method.addr}`;
      const cached = decompileCache.current.get(cacheKey);
      if (cached) {
        setDecompileContent(cached);
        setDecompileError(null);
        return;
      }
      setDecompileLoading(true);
      setDecompileError(null);
      setDecompileContent("");
      try {
        const disasm = strip.r2(htmlToPlain(await disassembleAt(method.addr, "html")));
        const prompt = [
          "Decompile the following Dalvik bytecode into equivalent Java source code.",
          "Output ONLY raw source code. No markdown, no code fences, no explanations.",
          "",
          `Class: ${cls.name}`,
          `Method: ${method.signature}`,
          "",
          "Bytecode:",
          disasm,
        ].join("\n");

        const res = await fetch("/api/llm/stream", {
          method: "POST",
          body: prompt,
        });
        if (!res.ok) throw new Error(await res.text());

        const reader = res.body!.getReader();
        const decoder = new TextDecoder();
        let accumulated = "";
        for (;;) {
          const { done, value } = await reader.read();
          if (done) break;
          accumulated += decoder.decode(value, { stream: true });
          setDecompileContent(accumulated);
        }
        decompileCache.current.set(cacheKey, accumulated);
      } catch (e) {
        setDecompileError(
          e instanceof Error ? e.message : "Decompilation failed",
        );
      } finally {
        setDecompileLoading(false);
      }
    },
    [disassembleAt],
  );

  const changeViewMode = useCallback(
    (mode: ViewMode) => {
      setViewMode(mode);
      if (mode === "graph" && selectedMethod) loadCFG();
      if (mode === "decompile" && selectedClass && selectedMethod) {
        decompileMethod(selectedClass, selectedMethod);
      }
    },
    [selectedClass, selectedMethod, decompileMethod, loadCFG],
  );

  const handleStringClick = useCallback(
    async (s: DexString) => {
      setSelectedString(s);
      setSelectedClass(null);
      setSelectedMethod(null);
      setViewMode("disassembly");
      setStringXrefs([]);
      const xrefs = await findStringXrefs(s.vaddr);
      setStringXrefs(xrefs);
    },
    [findStringXrefs],
  );

  const handleXrefClick = useCallback(
    async (xref: StringXref) => {
      // Find method by function address (compare numerically to handle zero-padding)
      const targetAddr = xref.fcnAddr;
      for (const cls of classes) {
        const method = cls.methods.find(
          (m) => parseInt(m.addr, 16) === targetAddr,
        );
        if (method) {
          setExpandedClasses((prev) => new Set(prev).add(cls.name));
          handleMethodClick(cls, method);
          return;
        }
      }
    },
    [classes, handleMethodClick],
  );

  const changeLeftTab = useCallback((tab: LeftTab) => {
    setLeftTab(tab);
    localStorage.setItem("dex-left-tab", tab);
  }, []);

  const fileName =
    params?.entry?.split("/").pop() ??
    params?.path?.split("/").pop() ??
    "classes.dex";

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        <span className="text-sm">Fetching and analyzing with radare2...</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {error}
      </div>
    );
  }

  if (!isReady) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-4 py-1.5 border-b flex-wrap shrink-0">
        <span className="text-xs font-mono text-muted-foreground truncate max-w-62.5">
          {fileName}
        </span>
        <Badge variant="outline" className="text-[10px]">
          {classes.length} classes
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          {totalMethods} methods
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          {strings.length} strings
        </Badge>
      </div>

      <ResizablePanelGroup
        orientation="horizontal"
        autoSaveId="dex-viewer"
        className="flex-1"
      >
        <ResizablePanel defaultSize="35%" minSize="20%">
          <Tabs
            value={leftTab}
            onValueChange={(v) => changeLeftTab(v as LeftTab)}
            className="h-full flex flex-col"
          >
            <TabsList variant="line" className="shrink-0">
              <TabsTrigger value="classes">
                Classes ({classes.length})
              </TabsTrigger>
              <TabsTrigger value="strings">
                Strings ({strings.length})
              </TabsTrigger>
            </TabsList>

            <TabsContent
              value="classes"
              className="flex-1 overflow-hidden flex flex-col"
            >
              <div className="px-2 py-1.5 border-b shrink-0">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search classes..."
                    value={classSearch}
                    onChange={(e) => setClassSearch(e.target.value)}
                    className="pl-8 h-7 text-xs"
                  />
                </div>
                <div className="text-[10px] text-muted-foreground mt-1 px-0.5">
                  {filteredClasses.length} / {classes.length}
                </div>
              </div>
              <ClassTree
                classes={filteredClasses}
                expanded={expandedClasses}
                selectedClass={selectedClass}
                selectedMethod={selectedMethod}
                onClassClick={handleClassClick}
                onMethodClick={handleMethodClick}
              />
            </TabsContent>

            <TabsContent
              value="strings"
              className="flex-1 overflow-hidden flex flex-col"
            >
              <div className="px-2 py-1.5 border-b shrink-0">
                <div className="relative">
                  <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                  <Input
                    placeholder="Search strings..."
                    value={strSearch}
                    onChange={(e) => setStrSearch(e.target.value)}
                    className="pl-8 h-7 text-xs"
                  />
                </div>
                <div className="text-[10px] text-muted-foreground mt-1 px-0.5">
                  {filteredStrings.length} / {strings.length}
                </div>
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

        <ResizablePanel defaultSize="65%" minSize="30%">
          {selectedString && viewMode === "disassembly" ? (
            <div className="h-full flex flex-col">
              <div className="flex items-center gap-2 px-3 py-1.5 border-b shrink-0">
                <Badge variant="secondary" className="text-[10px]">
                  string #{selectedString.index}
                </Badge>
              </div>
              <div className="flex-1 overflow-auto p-3">
                <pre className="font-mono text-xs whitespace-pre-wrap break-all mb-4">
                  {selectedString.value || (
                    <span className="text-muted-foreground italic">
                      (empty)
                    </span>
                  )}
                </pre>
                <div className="text-xs text-muted-foreground mb-2">
                  {stringXrefs.length > 0
                    ? `${stringXrefs.length} cross-reference${stringXrefs.length > 1 ? "s" : ""}`
                    : "No cross-references found"}
                </div>
                {stringXrefs.map((xref, i) => (
                  <button
                    key={`${xref.addr}-${i}`}
                    type="button"
                    className="block w-full text-left font-mono text-xs px-2 py-1 rounded hover:bg-accent/50 truncate"
                    onClick={() => handleXrefClick(xref)}
                    title={xref.fcnName}
                  >
                    <span className="text-muted-foreground">{xref.addr}</span>{" "}
                    <span className="text-amber-600 dark:text-amber-400 hover:underline">
                      {xref.fcnName}
                    </span>
                  </button>
                ))}
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col">
              <div className="flex items-center border-b shrink-0">
                {selectedMethod ? (
                  <Tabs
                    value={viewMode}
                    onValueChange={(v) => changeViewMode(v as ViewMode)}
                  >
                    <TabsList variant="line">
                      <TabsTrigger value="disassembly">Disassembly</TabsTrigger>
                      <TabsTrigger value="graph">Graph</TabsTrigger>
                      <TabsTrigger value="decompile">AI Decompile</TabsTrigger>
                    </TabsList>
                  </Tabs>
                ) : null}
                <span className="text-[10px] text-muted-foreground ml-auto pr-3 truncate max-w-[50%]">
                  {selectedMethod
                    ? `${selectedClass?.name}.${selectedMethod.name}`
                    : (selectedClass?.name ?? "Select a class or method")}
                </span>
              </div>
              <div className="flex-1 overflow-hidden">
                {!codeHtml && !decompileContent ? (
                  <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                    Click a class or method to view details
                  </div>
                ) : viewMode === "graph" ? (
                  cfgLoading ? (
                    <div className="flex items-center justify-center h-full text-muted-foreground">
                      <Loader2 className="h-4 w-4 animate-spin mr-2" />
                      Loading graph...
                    </div>
                  ) : cfgData ? (
                    <CFGView nodes={cfgData.nodes} edges={cfgData.edges} />
                  ) : (
                    <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                      No graph data available
                    </div>
                  )
                ) : viewMode === "decompile" && selectedMethod ? (
                  <DecompileView
                    content={decompileContent}
                    isLoading={decompileLoading}
                    error={decompileError}
                    theme={theme}
                    onRetry={
                      selectedClass && selectedMethod
                        ? () => decompileMethod(selectedClass!, selectedMethod!)
                        : undefined
                    }
                  />
                ) : (
                  <div className="h-full overflow-auto">
                    <pre
                      className="p-3 m-0 text-xs leading-[1.4] font-mono"
                      dangerouslySetInnerHTML={{ __html: codeHtml }}
                    />
                  </div>
                )}
              </div>
            </div>
          )}
        </ResizablePanel>
      </ResizablePanelGroup>
    </div>
  );
}

function DecompileView({
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
  onRetry?: () => void;
}) {
  if (isLoading && !content) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        Decompiling...
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
              <p className="text-sm font-medium">LLM not configured</p>
              <p className="text-xs text-muted-foreground">
                Decompilation requires an LLM provider. Set these environment
                variables before starting the server:
              </p>
              <pre className="text-[11px] text-left bg-muted rounded-md px-3 py-2 w-full font-mono">
                {`LLM_PROVIDER=anthropic   # or openai, gemini, openrouter\nLLM_API_KEY=sk-...\nLLM_MODEL=claude-sonnet-4-20250514`}
              </pre>
            </>
          ) : (
            <>
              <p className="text-sm font-medium">Decompilation failed</p>
              <p className="text-xs text-muted-foreground break-all">{error}</p>
            </>
          )}
          {onRetry && !isNotConfigured && (
            <Button
              variant="outline"
              size="sm"
              className="text-xs"
              onClick={onRetry}
            >
              Retry
            </Button>
          )}
        </div>
      </div>
    );
  }

  if (!content) {
    return (
      <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
        Select a method and switch to Decompile view
      </div>
    );
  }

  return (
    <Editor
      height="100%"
      language="java"
      theme={theme === "dark" ? "vs-dark" : "light"}
      value={content}
      options={{ ...editorOpts, lineNumbers: "on" }}
    />
  );
}

function ClassTree({
  classes,
  expanded,
  selectedClass,
  selectedMethod,
  onClassClick,
  onMethodClick,
}: {
  classes: DexClass[];
  expanded: Set<string>;
  selectedClass: DexClass | null;
  selectedMethod: DexMethod | null;
  onClassClick: (cls: DexClass) => void;
  onMethodClick: (cls: DexClass, method: DexMethod) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);

  const flatItems = useMemo(() => {
    const items: Array<
      | { kind: "class"; cls: DexClass }
      | { kind: "method"; cls: DexClass; method: DexMethod }
    > = [];
    for (const cls of classes) {
      items.push({ kind: "class", cls });
      if (expanded.has(cls.name)) {
        for (const m of cls.methods) {
          items.push({ kind: "method", cls, method: m });
        }
      }
    }
    return items;
  }, [classes, expanded]);

  const virtualizer = useVirtualizer({
    count: flatItems.length,
    getScrollElement: () => parentRef.current,
    estimateSize: () => 28,
    overscan: 20,
  });

  return (
    <div
      ref={parentRef}
      className="flex-1 overflow-auto outline-none"
      tabIndex={0}
    >
      <div
        style={{
          height: `${virtualizer.getTotalSize()}px`,
          width: "100%",
          position: "relative",
        }}
      >
        {virtualizer.getVirtualItems().map((virtualRow) => {
          const item = flatItems[virtualRow.index];

          if (item.kind === "class") {
            const { cls } = item;
            const isExpanded = expanded.has(cls.name);
            const isSelected =
              selectedClass?.name === cls.name && !selectedMethod;

            return (
              <div
                key={`c-${cls.name}`}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                className={`absolute top-0 left-0 w-full px-2 py-1 cursor-pointer border-b border-border/40 hover:bg-accent/50 ${isSelected ? "bg-accent text-accent-foreground" : ""}`}
                style={{ transform: `translateY(${virtualRow.start}px)` }}
                onClick={() => onClassClick(cls)}
              >
                <div className="flex items-center gap-1 min-w-0">
                  <span className="w-3 h-3 shrink-0 flex items-center justify-center">
                    {cls.methods.length > 0 ? (
                      isExpanded ? (
                        <ChevronDown className="w-3 h-3" />
                      ) : (
                        <ChevronRight className="w-3 h-3" />
                      )
                    ) : null}
                  </span>
                  <span className="font-mono text-xs truncate" title={cls.name}>
                    {cls.name}
                  </span>
                  {cls.methods.length > 0 && (
                    <Badge
                      variant="outline"
                      className="text-[8px] px-1 py-0 ml-auto shrink-0"
                    >
                      {cls.methods.length}
                    </Badge>
                  )}
                </div>
              </div>
            );
          }

          const { cls, method } = item;
          const isSelected =
            selectedMethod?.addr === method.addr &&
            selectedClass?.name === cls.name;

          return (
            <div
              key={`m-${cls.name}-${method.addr}`}
              data-index={virtualRow.index}
              ref={virtualizer.measureElement}
              className={`absolute top-0 left-0 w-full pl-7 pr-2 py-1 cursor-pointer border-b border-border/20 hover:bg-accent/50 ${isSelected ? "bg-accent text-accent-foreground" : ""}`}
              style={{ transform: `translateY(${virtualRow.start}px)` }}
              onClick={() => onMethodClick(cls, method)}
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="text-[9px] font-medium shrink-0 text-muted-foreground">
                  {method.flags}
                </span>
                <span
                  className="font-mono text-[11px] truncate"
                  title={method.signature}
                >
                  {method.name}
                </span>
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
  strings: DexString[];
  selectedIndex: number | null;
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
    <div
      ref={parentRef}
      className="flex-1 overflow-auto outline-none"
      tabIndex={0}
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
              data-index={virtualRow.index}
              ref={virtualizer.measureElement}
              className={`absolute top-0 left-0 w-full px-2 py-1 cursor-pointer border-b border-border/40 hover:bg-accent/50 ${isSelected ? "bg-accent text-accent-foreground" : ""}`}
              style={{ transform: `translateY(${virtualRow.start}px)` }}
              onClick={() => onSelect(str)}
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="text-[10px] text-muted-foreground w-8 shrink-0 text-right tabular-nums">
                  {str.index}
                </span>
                <span className="font-mono text-xs truncate" title={str.value}>
                  {str.value || (
                    <span className="text-muted-foreground italic">
                      (empty)
                    </span>
                  )}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

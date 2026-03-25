import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import {
  Loader2,
  Search,
  ChevronRight,
  ChevronDown,
  AlertCircle,
} from "lucide-react";
import Editor, { loader } from "@monaco-editor/react";
import { useVirtualizer } from "@tanstack/react-virtual";

import { DALVIK_LANGUAGE_ID, monarchTokens } from "@/lib/syntax/dalvik";
import {
  parseDex,
  disassembleMethod,
  findStringXrefs,
  type DexFile,
  type DexClassDef,
  type DexClassMethod,
  type DexString,
  type StringXref,
} from "@/lib/dex";

import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { useSession } from "@/context/SessionContext";
import { useTheme } from "@/components/providers/ThemeProvider";

loader.init().then((monaco) => {
  if (
    !monaco.languages
      .getLanguages()
      .some((l: { id: string }) => l.id === DALVIK_LANGUAGE_ID)
  ) {
    monaco.languages.register({ id: DALVIK_LANGUAGE_ID });
    monaco.languages.setMonarchTokensProvider(
      DALVIK_LANGUAGE_ID,
      monarchTokens,
    );
  }
});

export interface DexViewerParams {
  path?: string;
  apk?: string;
  entry?: string;
}

type LeftTab = "classes" | "strings";
type ViewMode = "disassembly" | "decompile";

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

function formatHex(n: number): string {
  return "0x" + n.toString(16);
}

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

  const [dex, setDex] = useState<DexFile | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [loadPhase, setLoadPhase] = useState<"download" | "parse">("download");

  const [leftTab, setLeftTab] = useState<LeftTab>(
    () => (localStorage.getItem("dex-left-tab") as LeftTab) || "classes",
  );
  const [classSearch, setClassSearch] = useState("");
  const [strSearch, setStrSearch] = useState("");

  const [selectedClass, setSelectedClass] = useState<DexClassDef | null>(null);
  const [selectedMethod, setSelectedMethod] = useState<DexClassMethod | null>(
    null,
  );
  const [selectedString, setSelectedString] = useState<DexString | null>(null);
  const [codeContent, setCodeContent] = useState("");
  const [expandedClasses, setExpandedClasses] = useState<Set<string>>(
    new Set(),
  );
  const [stringXrefs, setStringXrefs] = useState<StringXref[]>([]);

  const [viewMode, setViewMode] = useState<ViewMode>("disassembly");
  const [decompileContent, setDecompileContent] = useState("");
  const [decompileLoading, setDecompileLoading] = useState(false);
  const [decompileError, setDecompileError] = useState<string | null>(null);
  const decompileCache = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    if (!device || pid === undefined) return;
    let ignore = false;
    setIsLoading(true);
    setError(null);
    setProgress(0);
    setLoadPhase("download");

    (async () => {
      try {
        let url: string;
        if (params?.apk && params?.entry) {
          const u = new URL(window.location.href);
          u.pathname = `/api/apk-entry/${device}/${pid}`;
          u.searchParams.set("apk", params.apk);
          u.searchParams.set("entry", params.entry);
          url = u.toString();
        } else if (params?.path) {
          const u = new URL(window.location.href);
          u.pathname = `/api/download/${device}/${pid}`;
          u.searchParams.set("path", params.path);
          url = u.toString();
        } else {
          throw new Error("No DEX file path specified");
        }

        const res = await fetch(url);
        if (!res.ok) throw new Error(`Failed to fetch DEX file: ${res.status}`);
        const contentLength = res.headers.get("content-length");
        const total = contentLength ? parseInt(contentLength, 10) : 0;

        let buffer: ArrayBuffer;
        if (!res.body || !total) {
          buffer = await res.arrayBuffer();
          if (ignore) return;
          setProgress(100);
        } else {
          const reader = res.body.getReader();
          const chunks: Uint8Array[] = [];
          let received = 0;
          for (;;) {
            const { done, value } = await reader.read();
            if (done) break;
            chunks.push(value);
            received += value.length;
            if (!ignore) setProgress(Math.round((received / total) * 100));
          }
          if (ignore) return;
          const merged = new Uint8Array(received);
          let off = 0;
          for (const c of chunks) {
            merged.set(c, off);
            off += c.length;
          }
          buffer = merged.buffer;
        }

        setLoadPhase("parse");
        const parsed = parseDex(buffer);
        if (ignore) return;
        setDex(parsed);
      } catch (e) {
        if (ignore) return;
        setError(e instanceof Error ? e.message : "Failed to parse DEX file");
      } finally {
        if (!ignore) setIsLoading(false);
      }
    })();
    return () => {
      ignore = true;
    };
  }, [device, pid, params?.path, params?.apk, params?.entry]);

  const filteredClasses = useMemo(() => {
    if (!dex) return [];
    if (!classSearch.trim()) return dex.classes;
    const q = classSearch.toLowerCase();
    return dex.classes.filter((c) => c.className.toLowerCase().includes(q));
  }, [dex, classSearch]);

  const filteredStrings = useMemo(() => {
    if (!dex) return [];
    if (!strSearch.trim()) return dex.strings;
    const q = strSearch.toLowerCase();
    return dex.strings.filter((s) => s.value.toLowerCase().includes(q));
  }, [dex, strSearch]);

  const toggleClass = useCallback((className: string) => {
    setExpandedClasses((prev) => {
      const next = new Set(prev);
      if (next.has(className)) next.delete(className);
      else next.add(className);
      return next;
    });
  }, []);

  const handleClassClick = useCallback(
    (cls: DexClassDef) => {
      setSelectedClass(cls);
      setSelectedMethod(null);
      setSelectedString(null);
      setViewMode("disassembly");
      toggleClass(cls.className);

      const lines: string[] = [];
      lines.push(`; ${cls.accessString} class ${cls.className}`);
      if (cls.superclassName) lines.push(`;   extends ${cls.superclassName}`);
      if (cls.interfaces.length > 0)
        lines.push(`;   implements ${cls.interfaces.join(", ")}`);
      if (cls.sourceFile) lines.push(`; source: ${cls.sourceFile}`);
      lines.push("");

      if (cls.staticFields.length > 0) {
        lines.push("; --- Static Fields ---");
        for (const f of cls.staticFields)
          lines.push(`;   ${f.accessString} ${f.type} ${f.name}`);
        lines.push("");
      }
      if (cls.instanceFields.length > 0) {
        lines.push("; --- Instance Fields ---");
        for (const f of cls.instanceFields)
          lines.push(`;   ${f.accessString} ${f.type} ${f.name}`);
        lines.push("");
      }

      const allMethods = [...cls.directMethods, ...cls.virtualMethods];
      if (allMethods.length > 0) {
        lines.push("; --- Methods ---");
        for (const m of allMethods) {
          const p = m.parameterTypes.join(", ");
          lines.push(`;   ${m.accessString} ${m.returnType} ${m.name}(${p})`);
          if (m.codeOff !== 0)
            lines.push(
              `;     registers=${m.registersSize} ins=${m.insSize} outs=${m.outsSize} code_size=${m.codeSize}`,
            );
        }
      }
      setCodeContent(lines.join("\n"));
    },
    [toggleClass],
  );

  const buildDisassembly = useCallback(
    (cls: DexClassDef, method: DexClassMethod): string => {
      if (!dex) return "";
      const lines: string[] = [];
      const p = method.parameterTypes.join(", ");
      lines.push(
        `; ${method.accessString} ${method.returnType} ${cls.className}.${method.name}(${p})`,
      );
      if (method.codeOff !== 0) {
        lines.push(
          `; registers=${method.registersSize} ins=${method.insSize} outs=${method.outsSize} code_size=${method.codeSize}`,
        );
        lines.push(`; code_offset=${formatHex(method.codeOff)}`);
      }
      lines.push("");
      lines.push(...disassembleMethod(dex, method));
      return lines.join("\n");
    },
    [dex],
  );

  const decompileMethod = useCallback(
    async (cls: DexClassDef, method: DexClassMethod) => {
      const cacheKey = `${cls.className}.${method.name}@${method.codeOff}`;
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
        const disasm = buildDisassembly(cls, method);
        const methodParams = method.parameterTypes.join(", ");
        const signature = `${method.accessString} ${method.returnType} ${method.name}(${methodParams})`;
        const prompt = [
          "Decompile the following Dalvik bytecode into equivalent Java source code.",
          "Output the complete Java method including its signature and body.",
          "Do not include explanations or markdown fences.",
          "",
          `Class: ${cls.className}`,
          cls.superclassName ? `Extends: ${cls.superclassName}` : "",
          `Method signature: ${signature}`,
          "",
          "Bytecode:",
          disasm,
        ]
          .filter(Boolean)
          .join("\n");

        const res = await fetch("/api/llm", { method: "POST", body: prompt });
        if (!res.ok) throw new Error(await res.text());
        const java = await res.text();
        decompileCache.current.set(cacheKey, java);
        setDecompileContent(java);
      } catch (e) {
        setDecompileError(
          e instanceof Error ? e.message : "Decompilation failed",
        );
      } finally {
        setDecompileLoading(false);
      }
    },
    [buildDisassembly],
  );

  const handleMethodClick = useCallback(
    (cls: DexClassDef, method: DexClassMethod) => {
      if (!dex) return;
      setSelectedClass(cls);
      setSelectedMethod(method);
      setSelectedString(null);
      setDecompileError(null);
      setDecompileContent("");
      setViewMode("disassembly");
      setCodeContent(buildDisassembly(cls, method));
    },
    [dex, buildDisassembly],
  );

  const changeViewMode = useCallback(
    (mode: ViewMode) => {
      setViewMode(mode);
      if (mode === "decompile" && selectedClass && selectedMethod) {
        decompileMethod(selectedClass, selectedMethod);
      }
    },
    [selectedClass, selectedMethod, decompileMethod],
  );

  const handleStringClick = useCallback(
    (s: DexString) => {
      if (!dex) return;
      setSelectedString(s);
      setSelectedClass(null);
      setSelectedMethod(null);
      setViewMode("disassembly");
      setStringXrefs(findStringXrefs(dex, s.index));
    },
    [dex],
  );

  const handleXrefClick = useCallback(
    (xref: StringXref) => {
      if (!dex) return;
      for (const cls of dex.classes) {
        const allMethods = [...cls.directMethods, ...cls.virtualMethods];
        const method = allMethods.find((m) => m.methodIdx === xref.methodIdx);
        if (method) {
          setSelectedClass(cls);
          setSelectedMethod(method);
          setSelectedString(null);
          setDecompileError(null);
          setDecompileContent("");
          setViewMode("disassembly");
          setCodeContent(buildDisassembly(cls, method));
          return;
        }
      }
    },
    [dex, buildDisassembly],
  );

  const changeLeftTab = useCallback((tab: LeftTab) => {
    setLeftTab(tab);
    localStorage.setItem("dex-left-tab", tab);
  }, []);

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <div className="flex items-center gap-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          <span className="text-sm">
            {loadPhase === "download"
              ? progress > 0
                ? `Downloading... ${progress}%`
                : "Downloading..."
              : "Parsing DEX..."}
          </span>
        </div>
        {loadPhase === "download" && progress > 0 && (
          <Progress value={progress} className="w-48 h-1.5" />
        )}
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

  if (!dex) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  const fileName =
    params?.entry?.split("/").pop() ??
    params?.path?.split("/").pop() ??
    "classes.dex";

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-3 px-4 py-1.5 border-b flex-wrap shrink-0">
        <span className="text-xs font-mono text-muted-foreground truncate max-w-62.5">
          {fileName}
        </span>
        <Badge variant="secondary" className="text-[10px]">
          {dex.header.magic.replace("dex\n", "DEX ")}
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          {formatSize(dex.header.fileSize)}
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          {dex.classes.length} classes
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          {dex.methods.length} methods
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          {dex.strings.length} strings
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
                Classes ({dex.classes.length})
              </TabsTrigger>
              <TabsTrigger value="strings">
                Strings ({dex.strings.length})
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
                  {filteredClasses.length} / {dex.classes.length}
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
                  {filteredStrings.length} / {dex.strings.length}
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
                    <span className="text-muted-foreground italic">(empty)</span>
                  )}
                </pre>
                <div className="text-xs text-muted-foreground mb-2">
                  {stringXrefs.length > 0
                    ? `${stringXrefs.length} cross-reference${stringXrefs.length > 1 ? "s" : ""}`
                    : "No cross-references found"}
                </div>
                {stringXrefs.map((xref, i) => (
                  <button
                    key={`${xref.methodIdx}-${xref.codeOffset}-${i}`}
                    type="button"
                    className="block w-full text-left font-mono text-xs px-2 py-1 rounded hover:bg-accent/50 truncate"
                    onClick={() => handleXrefClick(xref)}
                    title={`${xref.className}.${xref.methodName}`}
                  >
                    <span className="text-muted-foreground">{formatHex(xref.codeOffset)}</span>
                    {" "}
                    <span className="text-amber-600 dark:text-amber-400 hover:underline">
                      {xref.className}.{xref.methodName}
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
                      <TabsTrigger value="decompile">Decompile</TabsTrigger>
                    </TabsList>
                  </Tabs>
                ) : null}
                <span className="text-[10px] text-muted-foreground ml-auto pr-3 truncate max-w-[50%]">
                  {selectedMethod
                    ? `${selectedClass?.className}.${selectedMethod.name}`
                    : selectedClass
                      ? selectedClass.className
                      : "Select a class or method"}
                </span>
              </div>
              <div className="flex-1 overflow-hidden">
                {!codeContent && !decompileContent ? (
                  <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                    Click a class or method to view details
                  </div>
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
                  <Editor
                    height="100%"
                    language={DALVIK_LANGUAGE_ID}
                    theme={theme === "dark" ? "vs-dark" : "light"}
                    value={codeContent}
                    options={editorOpts}
                  />
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
  if (isLoading) {
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
  classes: DexClassDef[];
  expanded: Set<string>;
  selectedClass: DexClassDef | null;
  selectedMethod: DexClassMethod | null;
  onClassClick: (cls: DexClassDef) => void;
  onMethodClick: (cls: DexClassDef, method: DexClassMethod) => void;
}) {
  const parentRef = useRef<HTMLDivElement>(null);

  const flatItems = useMemo(() => {
    const items: Array<
      | { kind: "class"; cls: DexClassDef }
      | {
          kind: "method";
          cls: DexClassDef;
          method: DexClassMethod;
          isVirtual: boolean;
        }
    > = [];
    for (const cls of classes) {
      items.push({ kind: "class", cls });
      if (expanded.has(cls.className)) {
        for (const m of cls.directMethods)
          items.push({ kind: "method", cls, method: m, isVirtual: false });
        for (const m of cls.virtualMethods)
          items.push({ kind: "method", cls, method: m, isVirtual: true });
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
            const cls = item.cls;
            const isExpanded = expanded.has(cls.className);
            const isSelected =
              selectedClass?.className === cls.className && !selectedMethod;
            const methodCount =
              cls.directMethods.length + cls.virtualMethods.length;

            return (
              <div
                key={`c-${cls.className}`}
                data-index={virtualRow.index}
                ref={virtualizer.measureElement}
                className={`absolute top-0 left-0 w-full px-2 py-1 cursor-pointer border-b border-border/40 hover:bg-accent/50 ${isSelected ? "bg-accent text-accent-foreground" : ""}`}
                style={{ transform: `translateY(${virtualRow.start}px)` }}
                onClick={() => onClassClick(cls)}
              >
                <div className="flex items-center gap-1 min-w-0">
                  <span className="w-3 h-3 shrink-0 flex items-center justify-center">
                    {methodCount > 0 ? (
                      isExpanded ? (
                        <ChevronDown className="w-3 h-3" />
                      ) : (
                        <ChevronRight className="w-3 h-3" />
                      )
                    ) : null}
                  </span>
                  <span
                    className="font-mono text-xs truncate"
                    title={cls.className}
                  >
                    {cls.className}
                  </span>
                  <Badge
                    variant="outline"
                    className="text-[8px] px-1 py-0 ml-auto shrink-0"
                  >
                    {methodCount}
                  </Badge>
                </div>
              </div>
            );
          }

          const { cls, method, isVirtual } = item;
          const isSelected =
            selectedMethod?.methodIdx === method.methodIdx &&
            selectedClass?.className === cls.className;

          return (
            <div
              key={`m-${cls.className}-${method.methodIdx}`}
              data-index={virtualRow.index}
              ref={virtualizer.measureElement}
              className={`absolute top-0 left-0 w-full pl-7 pr-2 py-1 cursor-pointer border-b border-border/20 hover:bg-accent/50 ${isSelected ? "bg-accent text-accent-foreground" : ""}`}
              style={{ transform: `translateY(${virtualRow.start}px)` }}
              onClick={() => onMethodClick(cls, method)}
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span
                  className={`text-[9px] font-medium shrink-0 ${isVirtual ? "text-blue-500" : "text-green-500"}`}
                >
                  {isVirtual ? "V" : "D"}
                </span>
                <span
                  className="font-mono text-[11px] truncate"
                  title={`${method.name}(${method.parameterTypes.join(", ")}): ${method.returnType}`}
                >
                  {method.name}
                </span>
                {method.codeOff === 0 && (
                  <Badge
                    variant="outline"
                    className="text-[7px] px-1 py-0 shrink-0 text-muted-foreground"
                  >
                    {method.accessFlags & 0x100 ? "native" : "abstract"}
                  </Badge>
                )}
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

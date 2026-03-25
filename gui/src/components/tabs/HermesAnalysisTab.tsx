import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, Search } from "lucide-react";
import Editor, { loader } from "@monaco-editor/react";
import { HERMES_LANGUAGE_ID, monarchTokens } from "@/lib/syntax/hermes";
import { useVirtualizer } from "@tanstack/react-virtual";

import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { ButtonGroup, ButtonGroupText } from "@/components/ui/button-group";
import { useSession } from "@/context/SessionContext";
import { useTheme } from "@/components/providers/ThemeProvider";

loader.init().then((monaco) => {
  if (
    !monaco.languages
      .getLanguages()
      .some((l: { id: string }) => l.id === HERMES_LANGUAGE_ID)
  ) {
    monaco.languages.register({ id: HERMES_LANGUAGE_ID });
    monaco.languages.setMonarchTokensProvider(
      HERMES_LANGUAGE_ID,
      monarchTokens,
    );
  }
});

export interface HermesAnalysisParams {
  entryId: number;
  filename: string;
}

interface HBCInfo {
  version: number;
  sourceHash: string;
  fileLength: number;
  globalCodeIndex: number;
  functionCount: number;
  stringCount: number;
  identifierCount: number;
  overflowStringCount: number;
  regExpCount: number;
  cjsModuleCount: number;
  hasAsync: boolean;
  staticBuiltins: boolean;
}

interface HBCFunction {
  id: number;
  name: string;
  offset: number;
  size: number;
  paramCount: number;
}

interface HBCString {
  index: number;
  value: string;
  kind: string;
}

interface AnalysisData {
  info: HBCInfo;
  functions: HBCFunction[];
  strings: HBCString[];
}

type ViewMode = "disassembly" | "pseudocode";
type LeftTab = "functions" | "strings";

function formatHex(n: number): string {
  return "0x" + n.toString(16);
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / (1024 * 1024)).toFixed(1) + " MB";
}

export function HermesAnalysisTab({
  params,
}: IDockviewPanelProps<HermesAnalysisParams>) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { device, identifier } = useSession();

  const [data, setData] = useState<AnalysisData | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const [leftTab, setLeftTab] = useState<LeftTab>(
    () => (localStorage.getItem("hermes-left-tab") as LeftTab) || "functions",
  );
  const [funcSearch, setFuncSearch] = useState("");
  const [selectedFuncId, setSelectedFuncId] = useState<number | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>(
    () =>
      (localStorage.getItem("hermes-view-mode") as ViewMode) || "pseudocode",
  );

  const [codeContent, setCodeContent] = useState("");
  const [codeLoading, setCodeLoading] = useState(false);

  const [strSearch, setStrSearch] = useState("");
  const [strKindFilter, setStrKindFilter] = useState("all");
  const [selectedString, setSelectedString] = useState<HBCString | null>(null);

  // Fetch analysis
  useEffect(() => {
    if (!params?.entryId || !device || !identifier) return;

    let ignore = false;
    setIsLoading(true);
    setError(null);

    (async () => {
      try {
        const res = await fetch(
          `/api/hermes/${device}/${identifier}/analyze/${params.entryId}`,
        );
        if (!res.ok) throw new Error("Failed to analyze Hermes bytecode");
        const result = await res.json();
        if (ignore) return;
        setData(result);
      } catch (e) {
        if (ignore) return;
        setError(e instanceof Error ? e.message : "Failed to analyze");
      } finally {
        if (!ignore) setIsLoading(false);
      }
    })();

    return () => {
      ignore = true;
    };
  }, [params?.entryId, device, identifier]);

  // Fetch code content when function or view mode changes
  const fetchCode = useCallback(
    async (funcId: number | null, mode: ViewMode) => {
      if (!device || !identifier || !params?.entryId) return;

      setCodeLoading(true);
      try {
        const endpoint = mode === "disassembly" ? "disassemble" : "decompile";
        const params_ = new URLSearchParams();
        if (funcId !== null) params_.set("fn", String(funcId));
        if (mode === "pseudocode") params_.set("offsets", "1");
        const query = params_.size ? `?${params_}` : "";

        const res = await fetch(
          `/api/hermes/${device}/${identifier}/${endpoint}/${params.entryId}${query}`,
        );
        if (!res.ok) throw new Error(`Failed to ${endpoint}`);
        const result = await res.json();
        setCodeContent(result.source ?? "");
      } catch {
        setCodeContent(
          mode === "disassembly"
            ? "; Failed to disassemble"
            : "// Failed to decompile",
        );
      } finally {
        setCodeLoading(false);
      }
    },
    [device, identifier, params?.entryId],
  );

  // When selecting a function, load its code
  const handleFuncClick = useCallback(
    (funcId: number) => {
      setSelectedFuncId(funcId);
      setSelectedString(null);
      fetchCode(funcId, viewMode);
    },
    [viewMode, fetchCode],
  );

  const changeLeftTab = useCallback((tab: LeftTab) => {
    setLeftTab(tab);
    localStorage.setItem("hermes-left-tab", tab);
    if (tab === "functions") setSelectedString(null);
  }, []);

  const changeViewMode = useCallback(
    (mode: ViewMode) => {
      setViewMode(mode);
      localStorage.setItem("hermes-view-mode", mode);
      fetchCode(selectedFuncId, mode);
    },
    [selectedFuncId, fetchCode],
  );

  // Filtered functions
  const filteredFunctions = useMemo(() => {
    if (!data) return [];
    if (!funcSearch.trim()) return data.functions;
    const q = funcSearch.toLowerCase();
    return data.functions.filter((f) => f.name.toLowerCase().includes(q));
  }, [data, funcSearch]);

  // Filtered strings
  const filteredStrings = useMemo(() => {
    if (!data) return [];
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

  const downloadAll = useCallback(
    async (mode: "decompile" | "disassemble") => {
      if (!device || !identifier || !params?.entryId) return;
      const endpoint = mode === "disassemble" ? "disassemble" : "decompile";
      const query = "";
      try {
        const res = await fetch(
          `/api/hermes/${device}/${identifier}/${endpoint}/${params.entryId}${query}`,
        );
        if (!res.ok) return;
        const { source } = await res.json();
        const ext = mode === "disassemble" ? "asm" : "js";
        const blob = new Blob([source], { type: "text/plain" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `${params.filename?.replace(/\.[^.]+$/, "") ?? "hermes"}.${ext}`;
        a.click();
        URL.revokeObjectURL(url);
      } catch {
        /* ignore */
      }
    },
    [device, identifier, params?.entryId, params?.filename],
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}...
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

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  const editorLanguage =
    viewMode === "disassembly" ? HERMES_LANGUAGE_ID : "javascript";

  return (
    <div className="h-full flex flex-col">
      {/* Header info bar */}
      <div className="flex items-center gap-3 px-4 py-1.5 border-b flex-wrap shrink-0">
        <span className="text-xs font-mono text-muted-foreground truncate max-w-62.5">
          {params?.filename}
        </span>
        <Badge variant="secondary" className="text-[10px]">
          v{data.info.version}
        </Badge>
        <Badge variant="outline" className="text-[10px]">
          {formatSize(data.info.fileLength)}
        </Badge>
        <ButtonGroup className="ml-auto">
          <ButtonGroupText className="text-[10px] h-7">Save</ButtonGroupText>
          <Button
            variant="outline"
            size="sm"
            className="text-[10px] h-7 px-2"
            onClick={() => downloadAll("decompile")}
          >
            .js
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-[10px] h-7 px-2"
            onClick={() => downloadAll("disassemble")}
          >
            .asm
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-[10px] h-7 px-2"
            render={
              <a
                href={`/api/hermes/${device}/${identifier}/download/${params?.entryId}`}
                download={`${params?.filename?.replace(/\.[^.]+$/, "") ?? "hermes"}.hbc`}
              />
            }
          >
            .hbc
          </Button>
        </ButtonGroup>
      </div>

      {/* Main split view */}
      <ResizablePanelGroup
        orientation="horizontal"
        autoSaveId="hermes-analysis"
        className="flex-1"
      >
        {/* Left panel: functions / strings tabs */}
        <ResizablePanel defaultSize="35%" minSize="20%">
          <Tabs
            value={leftTab}
            onValueChange={(v) => changeLeftTab(v as LeftTab)}
            className="h-full flex flex-col"
          >
            <TabsList variant="line" className="shrink-0">
              <TabsTrigger value="functions">
                Functions ({data.info.functionCount})
              </TabsTrigger>
              <TabsTrigger value="strings">
                Strings ({data.info.stringCount})
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
                    placeholder="Search functions..."
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
                    placeholder="Search strings..."
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
                  <option value="all">All</option>
                  <option value="string">String</option>
                  <option value="identifier">Identifier</option>
                  <option value="predefined">Predefined</option>
                </select>
              </div>
              <div className="text-[10px] text-muted-foreground px-2.5 py-1">
                {filteredStrings.length} / {data.strings.length}
              </div>
              <StringList
                strings={filteredStrings}
                selectedIndex={selectedString?.index ?? null}
                onSelect={setSelectedString}
              />
            </TabsContent>
          </Tabs>
        </ResizablePanel>

        <ResizableHandle />

        {/* Right panel: code view or string detail */}
        <ResizablePanel defaultSize="65%" minSize="30%">
          {selectedString ? (
            <div className="h-full flex flex-col">
              <div className="flex items-center gap-2 px-3 py-1.5 border-b shrink-0">
                <Badge
                  variant={
                    selectedString.kind === "identifier"
                      ? "secondary"
                      : "outline"
                  }
                  className="text-[10px]"
                >
                  {selectedString.kind}
                </Badge>
                <span className="text-[10px] text-muted-foreground">
                  #{selectedString.index}
                </span>
              </div>
              <div className="flex-1 overflow-auto p-3">
                <pre className="font-mono text-xs whitespace-pre-wrap break-all">
                  {selectedString.value || (
                    <span className="text-muted-foreground italic">
                      (empty)
                    </span>
                  )}
                </pre>
              </div>
            </div>
          ) : (
            <div className="h-full flex flex-col">
              {/* Toolbar */}
              <div className="flex items-center border-b shrink-0">
                <Tabs
                  value={viewMode}
                  onValueChange={(v) => changeViewMode(v as ViewMode)}
                >
                  <TabsList variant="line">
                    <TabsTrigger value="pseudocode">Pseudocode</TabsTrigger>
                    <TabsTrigger value="disassembly">Disassembly</TabsTrigger>
                  </TabsList>
                </Tabs>

                <span className="text-[10px] text-muted-foreground ml-auto pr-3">
                  {selectedFuncId !== null
                    ? `#${selectedFuncId}${data.functions[selectedFuncId] ? ` — ${data.functions[selectedFuncId].name}` : ""}`
                    : "All functions"}
                </span>
              </div>

              {/* Editor */}
              <div className="flex-1 overflow-hidden">
                {codeLoading ? (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    Loading...
                  </div>
                ) : !codeContent ? (
                  <div className="flex items-center justify-center h-full text-sm text-muted-foreground">
                    Click a function to view its code
                  </div>
                ) : (
                  <Editor
                    height="100%"
                    language={editorLanguage}
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
          )}
        </ResizablePanel>
      </ResizablePanelGroup>
    </div>
  );
}

/** Virtualized function list for the left panel */
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
    estimateSize: () => 32,
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
              data-index={virtualRow.index}
              ref={virtualizer.measureElement}
              className={`absolute top-0 left-0 w-full px-2 py-1 cursor-pointer border-b border-transparent hover:bg-accent/50 ${
                isSelected ? "bg-accent text-accent-foreground" : ""
              }`}
              style={{
                transform: `translateY(${virtualRow.start}px)`,
              }}
              onClick={() => onSelect(func.id)}
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="text-[10px] text-muted-foreground w-6 shrink-0 text-right tabular-nums">
                  {func.id}
                </span>
                <span className="font-mono text-xs truncate" title={func.name}>
                  {func.name}
                </span>
              </div>
              <div className="flex items-center gap-2 ml-[30px] text-[10px] text-muted-foreground">
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

/** Virtualized string list for the left panel */
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
    estimateSize: () => 28,
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
              data-index={virtualRow.index}
              ref={virtualizer.measureElement}
              className={`absolute top-0 left-0 w-full px-2 py-1 cursor-pointer border-b border-border/40 hover:bg-accent/50 ${
                isSelected ? "bg-accent text-accent-foreground" : ""
              }`}
              style={{
                transform: `translateY(${virtualRow.start}px)`,
              }}
              onClick={() => onSelect(str)}
            >
              <div className="flex items-center gap-1.5 min-w-0">
                <span className="text-[10px] text-muted-foreground w-6 shrink-0 text-right tabular-nums">
                  {str.index}
                </span>
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

import { useR2 } from "@/lib/use-r2";

import "./DisassemblyTab.css";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { MermaidGraphView } from "@/components/shared/MermaidGraphView";
import Editor from "@monaco-editor/react";

export interface DisassemblyTabParams {
  address: string;
  name?: string;
}

type ViewMode = "disassembly" | "graph" | "decompiler";

interface AnalysisResult {
  disassemblyHtml: string;
  graphData: string;
  decompilerOutput: string;
}

export function FruityDisassemblyTab({
  params,
}: IDockviewPanelProps<DisassemblyTabParams>) {
  const { t } = useTranslation();
  const address = params?.address || "";
  const [viewMode, setViewMode] = useState<ViewMode>("disassembly");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadingView, setLoadingView] = useState<ViewMode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { executeR2Command } = useR2();

  // Analyze function once on mount
  useEffect(() => {
    if (!address || !executeR2Command) return;

    let ignore = false;
    setIsLoading(true);
    setError(null);

    async function analyze() {
      try {
        // Analyze function at address, then get full function disassembly
        // Try function-aware disassembly first, fallback to pd 50
        let disassemblyHtml = await executeR2Command(
          `s ${address}; af; pdf`,
        );

        if (ignore) return;

        // If pdf returned empty/error, fallback to pd 50
        if (
          !disassemblyHtml.trim() ||
          disassemblyHtml.includes("Cannot find function")
        ) {
          disassemblyHtml = await executeR2Command(`s ${address}; pd 50`);
        }

        if (ignore) return;

        setResult({
          disassemblyHtml: disassemblyHtml.trimEnd(),
          graphData: "",
          decompilerOutput: "",
        });
        setIsLoading(false);
      } catch (e) {
        if (ignore) return;
        setError(e instanceof Error ? e.message : "Failed to disassemble");
        setIsLoading(false);
      }
    }

    analyze();

    return () => {
      ignore = true;
    };
  }, [address, executeR2Command]);

  // Lazy-load graph data when switching to graph tab
  const loadGraph = useCallback(async () => {
    if (!executeR2Command || result?.graphData) return;
    setLoadingView("graph");
    try {
      // Try mermaid output first, then dot, then JSON
      let graphData = await executeR2Command(
        `s ${address}; af; agfm`,
        { output: "plain" },
      );

      if (!graphData.trim() || graphData.includes("Cannot find function")) {
        // Try agfd (dot format) as fallback
        graphData = await executeR2Command(
          `s ${address}; af; agfd`,
          { output: "plain" },
        );
      }

      setResult((prev) =>
        prev ? { ...prev, graphData: graphData.trimEnd() } : prev,
      );
    } catch {
      // Graph not available for this function
      setResult((prev) =>
        prev
          ? { ...prev, graphData: "graph TD\n  A[Graph not available]" }
          : prev,
      );
    } finally {
      setLoadingView(null);
    }
  }, [address, executeR2Command, result?.graphData]);

  // Lazy-load decompiler output when switching to decompiler tab
  const loadDecompiler = useCallback(async () => {
    if (!executeR2Command || result?.decompilerOutput) return;
    setLoadingView("decompiler");
    try {
      const output = await executeR2Command(
        `e scr.color=0; s ${address}; af; pdc; e scr.color=3`,
        { output: "plain" },
      );
      setResult((prev) =>
        prev ? { ...prev, decompilerOutput: output.trimEnd() } : prev,
      );
    } catch {
      setResult((prev) =>
        prev
          ? {
              ...prev,
              decompilerOutput: "// Decompiler not available for this function",
            }
          : prev,
      );
    } finally {
      setLoadingView(null);
    }
  }, [address, executeR2Command, result?.decompilerOutput]);

  const handleTabChange = (value: string) => {
    const mode = value as ViewMode;
    setViewMode(mode);
    if (mode === "graph") loadGraph();
    if (mode === "decompiler") loadDecompiler();
  };

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

  if (!result) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <Tabs
        value={viewMode}
        onValueChange={handleTabChange}
        className="h-full flex flex-col"
      >
        <div className="flex items-center border-b bg-[#1b1b1f]">
          <TabsList variant="line">
            <TabsTrigger value="disassembly">Linear</TabsTrigger>
            <TabsTrigger value="graph">Graph</TabsTrigger>
            <TabsTrigger value="decompiler">Decompiler</TabsTrigger>
          </TabsList>
          <span className="text-xs font-mono text-muted-foreground px-3 py-1.5 truncate ml-auto max-w-[40%]">
            {params?.name || address}
          </span>
        </div>

        <TabsContent value="disassembly" className="flex-1 overflow-hidden">
          <div className="disassembly-view h-full overflow-auto p-3">
            {/* r2 WASM output — trusted local source, not user input */}
            <div dangerouslySetInnerHTML={{ __html: result.disassemblyHtml }} />
          </div>
        </TabsContent>

        <TabsContent value="graph" className="flex-1 overflow-hidden">
          {loadingView === "graph" ? (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
              Loading graph...
            </div>
          ) : (
            <MermaidGraphView graphData={result.graphData} />
          )}
        </TabsContent>

        <TabsContent value="decompiler" className="flex-1 overflow-hidden">
          {loadingView === "decompiler" ? (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin mr-2" />
              Loading decompiler...
            </div>
          ) : (
            <Editor
              height="100%"
              language="c"
              theme="vs-dark"
              value={result.decompilerOutput}
              options={{
                readOnly: true,
                minimap: { enabled: false },
                fontSize: 13,
                fontFamily:
                  "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
                lineNumbers: "on",
                scrollBeyondLastLine: false,
                wordWrap: "on",
              }}
            />
          )}
        </TabsContent>
      </Tabs>
    </div>
  );
}

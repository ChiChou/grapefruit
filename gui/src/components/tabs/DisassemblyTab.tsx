import { useR2 } from "@/lib/use-r2";

import "./DisassemblyTab.css";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { CFGView, type CFGNode, type CFGEdge } from "@/components/shared/CFGView";
import Editor from "@monaco-editor/react";

export interface DisassemblyTabParams {
  address: string;
  name?: string;
}

type ViewMode = "disassembly" | "graph" | "decompiler";

interface AnalysisResult {
  disassemblyHtml: string;
  graphNodes: CFGNode[];
  graphEdges: CFGEdge[];
  decompilerOutput: string;
}

// r2 analysis setup: moderate depth to avoid WASM stack overflow
const analysisSetup = `e anal.depth=64; e anal.hasnext=true`;

export function DisassemblyTab({
  params,
}: IDockviewPanelProps<DisassemblyTabParams>) {
  const { t } = useTranslation();
  const address = params?.address || "";
  const [viewMode, setViewMode] = useState<ViewMode>("disassembly");
  const [result, setResult] = useState<AnalysisResult | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [loadingView, setLoadingView] = useState<ViewMode | null>(null);
  const [error, setError] = useState<string | null>(null);
  const { executeR2Command, isReady } = useR2();

  // Analyze function once r2 is ready
  useEffect(() => {
    if (!address || !isReady) return;

    let ignore = false;
    setIsLoading(true);
    setError(null);

    async function analyze() {
      try {
        let disassemblyHtml = await executeR2Command(
          `${analysisSetup}; s ${address}; af; pdf`,
        );

        if (ignore) return;

        if (
          !disassemblyHtml.trim() ||
          disassemblyHtml.includes("Cannot find function")
        ) {
          disassemblyHtml = await executeR2Command(`s ${address}; pd 50`);
        }

        if (ignore) return;

        setResult({
          disassemblyHtml: disassemblyHtml.trimEnd(),
          graphNodes: [],
          graphEdges: [],
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
  }, [address, isReady, executeR2Command]);

  // Lazy-load graph data when switching to graph tab
  const loadGraph = useCallback(async () => {
    if (!executeR2Command || (result?.graphNodes && result.graphNodes.length > 0)) return;
    setLoadingView("graph");
    try {
      const raw = await executeR2Command(
        `${analysisSetup}; s ${address}; af; agfj`,
        { output: "plain" },
      );

      const nodes: CFGNode[] = [];
      const edges: CFGEdge[] = [];
      const parsed = JSON.parse(raw);
      const blocks: Array<{
        offset: number;
        size: number;
        ops?: Array<{ offset: number; disasm?: string; type?: string }>;
        jump?: number;
        fail?: number;
      }> = Array.isArray(parsed) && parsed.length > 0
        ? parsed[0].blocks ?? []
        : [];

      for (const block of blocks) {
        const id = `bb_${block.offset.toString(16)}`;
        const lines = (block.ops ?? []).map(
          (op) => op.disasm ?? `unknown @ 0x${op.offset.toString(16)}`,
        );
        nodes.push({ id, label: `0x${block.offset.toString(16)}`, lines });
        if (block.jump !== undefined) {
          const targetId = `bb_${block.jump.toString(16)}`;
          const type = block.fail !== undefined ? "true" : "unconditional";
          edges.push({ from: id, to: targetId, type });
        }
        if (block.fail !== undefined) {
          const targetId = `bb_${block.fail.toString(16)}`;
          edges.push({ from: id, to: targetId, type: "false" });
        }
      }

      setResult((prev) =>
        prev ? { ...prev, graphNodes: nodes, graphEdges: edges } : prev,
      );
    } catch {
      setResult((prev) =>
        prev ? { ...prev, graphNodes: [], graphEdges: [] } : prev,
      );
    } finally {
      setLoadingView(null);
    }
  }, [address, executeR2Command, result?.graphNodes]);

  // Lazy-load decompiler output when switching to decompiler tab
  const loadDecompiler = useCallback(async () => {
    if (!executeR2Command || result?.decompilerOutput) return;
    setLoadingView("decompiler");
    try {
      // Deep analysis needed for complete decompilation with all basic blocks
      const output = await executeR2Command(
        `${analysisSetup}; e scr.color=0; s ${address}; af; pdc; e scr.color=3`,
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
            <CFGView nodes={result.graphNodes} edges={result.graphEdges} />
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

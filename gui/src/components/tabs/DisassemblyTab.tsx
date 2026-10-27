import { useR2Session } from "@/lib/use-r2-session";
import * as decompiler from "@/lib/decompiler";
import { Decompiler } from "@/components/shared/Decompiler";

import "./DisassemblyTab.css";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import {
  AlertCircle,
  Loader2,
  Binary,
  Pencil,
} from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { CFGView, type CFGNode, type CFGEdge } from "@/components/shared/CFGView";
import { Button } from "@/components/ui/button";
import { DisassemblyMinimap } from "@/components/shared/DisassemblyMinimap";
import { RenameDialog } from "@/components/shared/RenameDialog";

export interface DisassemblyTabParams {
  address: string;
  name?: string;
}

type ViewMode = "disassembly" | "graph" | "decompiler";

interface AnalysisResult {
  disassemblyHtml: string;
  graphNodes: CFGNode[];
  graphEdges: CFGEdge[];
}

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
  const [showBytes, setShowBytes] = useState(false);
  const { cmd, disassemble, graph, isReady, error: sessionError } = useR2Session();

  const [renameOpen, setRenameOpen] = useState(false);

  const fetchDisassembly = useCallback(
    async (withBytes: boolean) => {
      if (withBytes) {
        return cmd(`e asm.bytes=true; e asm.nbytes=8; s ${address}; af; pdf`, { output: "html" });
      }
      let html = await disassemble(address, { output: "html" });
      if (!html?.trim()) {
        html = await cmd(`s ${address}; pd 50`, { output: "html" });
      }
      return html ?? "";
    },
    [address, cmd, disassemble],
  );

  useEffect(() => {
    if (!address || !isReady) return;

    let ignore = false;
    setIsLoading(true);
    setError(null);

    async function analyze() {
      try {
        const html = await fetchDisassembly(showBytes);
        if (ignore) return;

        setResult({
          disassemblyHtml: (html ?? "").trimEnd(),
          graphNodes: [],
          graphEdges: [],
        });
        setIsLoading(false);
      } catch (e) {
        if (ignore) return;
        setError(e instanceof Error ? e.message : String(e));
        setIsLoading(false);
      }
    }

    analyze();
    return () => { ignore = true; };
  }, [address, isReady, showBytes, fetchDisassembly]);

  const toggleBytes = useCallback(async () => {
    const next = !showBytes;
    setShowBytes(next);
    if (result) {
      try {
        const html = await fetchDisassembly(next);
        setResult((prev) => prev ? { ...prev, disassemblyHtml: html.trimEnd() } : prev);
      } catch {}
    }
  }, [showBytes, result, fetchDisassembly]);

  const loadGraph = useCallback(async () => {
    if (!isReady || (result?.graphNodes && result.graphNodes.length > 0)) return;
    setLoadingView("graph");
    try {
      const cfg = await graph(address);
      const nodes: CFGNode[] = [];
      const edges: CFGEdge[] = [];
      if (cfg?.blocks) {
        for (const block of cfg.blocks) {
          const id = `bb_${block.addr.toString(16)}`;
          const lines = (block.ops ?? []).map(
            (op: { disasm?: string; offset: number }) =>
              op.disasm ?? `unknown @ 0x${op.offset.toString(16)}`,
          );
          nodes.push({ id, label: `0x${block.addr.toString(16)}`, lines });
          if (block.jump !== undefined) {
            edges.push({
              from: id,
              to: `bb_${block.jump.toString(16)}`,
              type: block.fail !== undefined ? "true" : "unconditional",
            });
          }
          if (block.fail !== undefined) {
            edges.push({ from: id, to: `bb_${block.fail.toString(16)}`, type: "false" });
          }
        }
      }
      setResult((prev) => prev ? { ...prev, graphNodes: nodes, graphEdges: edges } : prev);
    } catch {
      setResult((prev) => prev ? { ...prev, graphNodes: [], graphEdges: [] } : prev);
    } finally {
      setLoadingView(null);
    }
  }, [address, isReady, graph, result?.graphNodes]);

  const load = useCallback(async (signal: AbortSignal) => {
    const input = await decompiler.snapshot(cmd, address);
    signal.throwIfAborted();
    return decompiler.decompile(input, signal);
  }, [cmd, address]);

  const handleTabChange = (value: string) => {
    const mode = value as ViewMode;
    setViewMode(mode);
    if (mode === "graph") loadGraph();
  };

  const handleRename = useCallback(async (newName: string) => {
    try {
      await cmd(`afn ${newName} @ ${address}`);
      // Re-fetch disassembly to reflect new name
      const html = await fetchDisassembly(showBytes);
      setResult((prev) => prev ? { ...prev, disassemblyHtml: html.trimEnd() } : prev);
    } catch {}
  }, [cmd, address, fetchDisassembly, showBytes]);

  if (sessionError) {
    return (
      <div className="flex items-center justify-center h-full px-6">
        <div className="flex flex-col items-center gap-3 max-w-lg text-center">
          <AlertCircle className="h-8 w-8 text-destructive" />
          <p className="text-sm font-medium">Failed to start R2 session</p>
          <p className="text-xs text-muted-foreground break-all font-mono">{sessionError}</p>
        </div>
      </div>
    );
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {isReady ? `${t("loading")}...` : "Starting r2 session..."}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full px-6">
        <div className="flex flex-col items-center gap-3 max-w-lg text-center">
          <AlertCircle className="h-8 w-8 text-destructive" />
          <p className="text-sm font-medium">Disassembly failed</p>
          <p className="text-xs text-muted-foreground break-all font-mono">{error}</p>
        </div>
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
    <div className="h-full flex">
      <Tabs value={viewMode} onValueChange={handleTabChange} className="h-full flex flex-col flex-1 min-w-0">
        <div className="flex items-center border-b bg-card">
          <TabsList variant="line">
            <TabsTrigger value="disassembly">Linear</TabsTrigger>
            <TabsTrigger value="graph">Graph</TabsTrigger>
            <TabsTrigger value="decompiler">Decompiler</TabsTrigger>
          </TabsList>
          <div className="flex items-center gap-0.5 ml-auto px-2">
            <Button
              variant="ghost"
              size="sm"
              className={`h-6 w-6 p-0 ${showBytes ? "text-primary" : ""}`}
              onClick={toggleBytes}
              title="Toggle opcode bytes"
            >
              <Binary className="h-3.5 w-3.5" />
            </Button>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 w-6 p-0"
              onClick={() => setRenameOpen(true)}
              title="Rename function"
            >
              <Pencil className="h-3.5 w-3.5" />
            </Button>
          </div>
          <span className="text-xs font-mono text-muted-foreground px-3 py-1.5 truncate max-w-[30%]">
            {params?.name || address}
          </span>
        </div>

        <TabsContent value="disassembly" className="flex-1 overflow-hidden">
          <div className="disassembly-view h-full overflow-auto">
            <pre
              className="p-3 m-0 text-[13px] leading-[1.4] font-mono"
              dangerouslySetInnerHTML={{ __html: result.disassemblyHtml }}
            />
          </div>
        </TabsContent>

        <TabsContent value="graph" className="flex-1 overflow-hidden">
          {loadingView === "graph" ? (
            <div className="flex items-center justify-center h-full text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin mr-2" />Loading graph...
            </div>
          ) : (
            <CFGView nodes={result.graphNodes} edges={result.graphEdges} fnName={params?.name} />
          )}
        </TabsContent>

        <TabsContent value="decompiler" className="flex-1 overflow-hidden">
          {viewMode === "decompiler" && <Decompiler load={load} live />}
        </TabsContent>
      </Tabs>
      <DisassemblyMinimap cmd={async (c) => cmd(c)} isReady={isReady} currentAddr={address} />

      <RenameDialog
        open={renameOpen}
        onOpenChange={setRenameOpen}
        currentName={params?.name || ""}
        address={address}
        onRename={handleRename}
      />
    </div>
  );
}

import { useR2Session } from "@/lib/use-r2-session";

import "./DisassemblyTab.css";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { AlertCircle, Loader2 } from "lucide-react";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { CFGView, type CFGNode, type CFGEdge } from "@/components/shared/CFGView";
import { Button } from "@/components/ui/button";
import Editor from "@monaco-editor/react";

export interface DisassemblyTabParams {
  address: string;
  name?: string;
}

type ViewMode = "disassembly" | "graph" | "decompiler" | "ai-decompile";

interface AnalysisResult {
  disassemblyHtml: string;
  plainDisasm: string;
  graphNodes: CFGNode[];
  graphEdges: CFGEdge[];
  decompilerOutput: string;
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
  const { cmd, disassemble, graph, isReady, error: sessionError } = useR2Session();

  const [aiContent, setAiContent] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [aiError, setAiError] = useState<string | null>(null);
  const aiCache = useRef<Map<string, string>>(new Map());

  useEffect(() => {
    if (!address || !isReady) return;

    let ignore = false;
    setIsLoading(true);
    setError(null);

    async function analyze() {
      try {
        let html = await disassemble(address, { output: "html" });
        if (ignore) return;

        if (!html?.trim()) {
          html = await cmd(`s ${address}; pd 50`, { output: "html" });
        }
        if (ignore) return;

        let plain = "";
        try {
          plain = (await disassemble(address)) ?? "";
          if (!plain.trim()) {
            plain = await cmd(`s ${address}; pd 50`);
          }
        } catch {
          // plain text is optional (used for AI decompile)
        }
        if (ignore) return;

        setResult({
          disassemblyHtml: (html ?? "").trimEnd(),
          plainDisasm: plain.trimEnd(),
          graphNodes: [],
          graphEdges: [],
          decompilerOutput: "",
        });
        setIsLoading(false);
      } catch (e) {
        if (ignore) return;
        const msg = e instanceof Error ? e.message : String(e);
        setError(msg);
        setIsLoading(false);
      }
    }

    analyze();
    return () => { ignore = true; };
  }, [address, isReady, cmd, disassemble]);

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
            const targetId = `bb_${block.jump.toString(16)}`;
            const type = block.fail !== undefined ? "true" : "unconditional";
            edges.push({ from: id, to: targetId, type });
          }
          if (block.fail !== undefined) {
            const targetId = `bb_${block.fail.toString(16)}`;
            edges.push({ from: id, to: targetId, type: "false" });
          }
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
  }, [address, isReady, graph, result?.graphNodes]);

  const loadDecompiler = useCallback(async () => {
    if (!isReady || result?.decompilerOutput) return;
    setLoadingView("decompiler");
    try {
      const output = await cmd(`e scr.color=0; s ${address}; af; pdc`);
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
  }, [address, isReady, cmd, result?.decompilerOutput]);

  const loadAiDecompile = useCallback(async () => {
    if (!result?.plainDisasm) return;

    const cached = aiCache.current.get(address);
    if (cached) {
      setAiContent(cached);
      setAiError(null);
      return;
    }

    setAiLoading(true);
    setAiError(null);
    setAiContent("");

    try {
      const name = params?.name || address;
      const prompt = [
        "Decompile the following disassembly into equivalent C/C++ source code.",
        "Output ONLY raw source code. No markdown, no code fences, no explanations.",
        "",
        `Function: ${name}`,
        `Address: ${address}`,
        "",
        "Disassembly:",
        result.plainDisasm,
      ].join("\n");

      const res = await fetch("/api/llm/stream", { method: "POST", body: prompt });
      if (!res.ok) throw new Error(await res.text());

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let accumulated = "";

      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        accumulated += decoder.decode(value, { stream: true });
        setAiContent(accumulated);
      }

      aiCache.current.set(address, accumulated);
    } catch (e) {
      setAiError(e instanceof Error ? e.message : "AI decompilation failed");
    } finally {
      setAiLoading(false);
    }
  }, [address, result?.plainDisasm, params?.name]);

  const handleTabChange = (value: string) => {
    const mode = value as ViewMode;
    setViewMode(mode);
    if (mode === "graph") loadGraph();
    if (mode === "decompiler") loadDecompiler();
    if (mode === "ai-decompile") loadAiDecompile();
  };

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
            <TabsTrigger value="ai-decompile">AI Decompile</TabsTrigger>
          </TabsList>
          <span className="text-xs font-mono text-muted-foreground px-3 py-1.5 truncate ml-auto max-w-[40%]">
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

        <TabsContent value="ai-decompile" className="flex-1 overflow-hidden">
          <AiDecompileView
            content={aiContent}
            isLoading={aiLoading}
            error={aiError}
            onRetry={loadAiDecompile}
          />
        </TabsContent>
      </Tabs>
    </div>
  );
}

function AiDecompileView({
  content,
  isLoading,
  error,
  onRetry,
}: {
  content: string;
  isLoading: boolean;
  error: string | null;
  onRetry: () => void;
}) {
  if (isLoading && !content) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        Decompiling with AI...
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
                AI decompilation requires an LLM provider. Set these environment
                variables before starting the server:
              </p>
              <pre className="text-[11px] text-left bg-muted rounded-md px-3 py-2 w-full font-mono">
                {`LLM_PROVIDER=anthropic   # or openai, gemini, openrouter\nLLM_API_KEY=sk-...\nLLM_MODEL=claude-sonnet-4-20250514`}
              </pre>
            </>
          ) : (
            <>
              <p className="text-sm font-medium">AI decompilation failed</p>
              <p className="text-xs text-muted-foreground break-all">{error}</p>
              <Button
                variant="outline"
                size="sm"
                className="text-xs"
                onClick={onRetry}
              >
                Retry
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
        Switch to this tab to decompile with AI
      </div>
    );
  }

  return (
    <Editor
      height="100%"
      language="c"
      theme="vs-dark"
      value={content}
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
  );
}

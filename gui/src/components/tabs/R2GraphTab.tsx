import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { useR2Session } from "@/lib/use-r2-session";
import { useR2 } from "@/context/R2Context";
import { CFGView, type CFGNode, type CFGEdge } from "@/components/shared/CFGView";

export function R2GraphTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { graph, isReady } = useR2Session();
  const { addr } = useR2();
  const [nodes, setNodes] = useState<CFGNode[]>([]);
  const [edges, setEdges] = useState<CFGEdge[]>([]);
  const [loading, setLoading] = useState(false);
  const [lastAddr, setLastAddr] = useState("");

  const load = useCallback(async () => {
    if (!isReady || !addr || addr === lastAddr) return;
    setLoading(true);
    setLastAddr(addr);
    try {
      const cfg = await graph(addr);
      const n: CFGNode[] = [];
      const e: CFGEdge[] = [];
      if (cfg?.blocks) {
        for (const block of cfg.blocks) {
          const id = `bb_${block.addr.toString(16)}`;
          const lines = (block.ops ?? []).map(
            (op: any) => op.disasm ?? `0x${op.offset.toString(16)}`,
          );
          n.push({ id, label: `0x${block.addr.toString(16)}`, lines });
          if (block.jump !== undefined) {
            e.push({
              from: id,
              to: `bb_${block.jump.toString(16)}`,
              type: block.fail !== undefined ? "true" : "unconditional",
            });
          }
          if (block.fail !== undefined) {
            e.push({ from: id, to: `bb_${block.fail.toString(16)}`, type: "false" });
          }
        }
      }
      setNodes(n);
      setEdges(e);
    } catch {
      setNodes([]);
      setEdges([]);
    } finally {
      setLoading(false);
    }
  }, [addr, isReady, graph, lastAddr]);

  useEffect(() => { load(); }, [load]);

  if (!addr) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
        {t("r2_seek_to_graph")}
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("r2_loading_graph")}
      </div>
    );
  }

  return <CFGView nodes={nodes} edges={edges} />;
}

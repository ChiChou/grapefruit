import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { useR2Session } from "@/lib/use-r2-session";
import { useR2 } from "@/context/R2Context";

import "../tabs/DisassemblyTab.css";

export function R2DisasmTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { cmd, disassemble, isReady } = useR2Session();
  const { addr, showBytes } = useR2();
  const [html, setHtml] = useState("");
  const [loading, setLoading] = useState(false);
  const [lastAddr, setLastAddr] = useState("");
  const [lastBytes, setLastBytes] = useState(false);

  const load = useCallback(async () => {
    if (!isReady || !addr) return;
    if (addr === lastAddr && showBytes === lastBytes) return;
    setLoading(true);
    setLastAddr(addr);
    setLastBytes(showBytes);
    try {
      if (showBytes) {
        const raw = await cmd(
          `e asm.bytes=true; e asm.nbytes=8; s ${addr}; af; pdf`,
          { output: "html" },
        );
        setHtml(raw ?? "");
      } else {
        let result = await disassemble(addr, { output: "html" });
        if (!result?.trim()) {
          result = await cmd(`s ${addr}; pd 50`, { output: "html" });
        }
        setHtml(result ?? "");
      }
    } catch {
      setHtml("");
    } finally {
      setLoading(false);
    }
  }, [addr, isReady, cmd, disassemble, showBytes, lastAddr, lastBytes]);

  useEffect(() => { load(); }, [load]);

  if (!addr) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
        {t("r2_seek_to_disasm")}
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("loading")}
      </div>
    );
  }

  return (
    <div className="disassembly-view h-full overflow-auto">
      <pre
        className="p-3 m-0 text-[13px] leading-[1.4] font-mono"
        dangerouslySetInnerHTML={{ __html: html }}
      />
    </div>
  );
}

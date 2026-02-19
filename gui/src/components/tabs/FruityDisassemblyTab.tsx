import { useR2 } from "@frida/react-use-r2";

import "./DisassemblyTab.css";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";

export interface DisassemblyTabParams {
  address: string;
  name?: string;
}

export function FruityDisassemblyTab({
  params,
}: IDockviewPanelProps<DisassemblyTabParams>) {
  const { t } = useTranslation();
  const address = params?.address || "";
  const [html, setHtml] = useState<string>("");
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { executeR2Command } = useR2();

  useEffect(() => {
    if (!address || !executeR2Command) return;

    let ignore = false;
    setIsLoading(true);
    setError(null);

    async function disassemble() {
      try {
        // Seek to address and disassemble
        const command = [`s ${address}`, "pd 50", "pdj 50"];
        const result = await executeR2Command(command.join(";"));

        if (ignore) return;

        const lines = result.trimEnd().split("\n");
        // Last line is JSON metadata from pdj, skip it
        const htmlContent = lines.slice(0, lines.length - 1).join("\n");

        setHtml(htmlContent);
        setIsLoading(false);
      } catch (e) {
        if (ignore) return;
        setError(e instanceof Error ? e.message : "Failed to disassemble");
        setIsLoading(false);
      }
    }

    disassemble();

    return () => {
      ignore = true;
    };
  }, [address, executeR2Command]);

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

  if (!html) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-2 p-2 border-b bg-[#1b1b1f] text-muted-foreground">
        <span className="text-xs font-mono">{params?.name || address}</span>
      </div>
      <div className="disassembly-view flex-1 overflow-auto p-3">
        <div dangerouslySetInnerHTML={{ __html: html }} />
      </div>
    </div>
  );
}

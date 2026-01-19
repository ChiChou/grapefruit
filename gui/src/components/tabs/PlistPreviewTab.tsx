import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { useSession } from "@/context/SessionContext";
import { ChevronDown, ChevronUp, FileJson } from "lucide-react";
import { Loader2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import PlistView, { type PlistValue } from "@/components/PlistView";

export interface PlistPreviewTabParams {
  path: string;
}

export function PlistPreviewTab({
  params,
}: IDockviewPanelProps<PlistPreviewTabParams>) {
  const { api, status } = useSession();
  const { t } = useTranslation();
  const [data, setData] = useState<PlistValue | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [expandAll, setExpandAll] = useState(false);

  const fullPath = params?.path || "";
  const apiReady = status === "ready" && !!api;

  const loadContent = useCallback(async () => {
    if (!apiReady || !fullPath) return;

    setIsLoading(true);
    setError(null);

    try {
      const result = await api.fs.plist(fullPath);
      setData(result);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load plist");
      setData(null);
    } finally {
      setIsLoading(false);
    }
  }, [api, apiReady, fullPath]);

  useEffect(() => {
    loadContent();
  }, [loadContent]);

  const handleExpandAll = () => setExpandAll(true);
  const handleCollapseAll = () => setExpandAll(false);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        {t("loading")}
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

  if (data === null) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_content")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex-none px-4 py-2 bg-muted/50 border-b flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileJson className="w-4 h-4 text-yellow-500" />
          <span className="truncate text-sm">{fullPath}</span>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="ghost"
            size="sm"
            className="h-8"
            onClick={handleExpandAll}
          >
            <ChevronDown className="w-4 h-4 mr-1" />
            {t("expand_all")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-8"
            onClick={handleCollapseAll}
          >
            <ChevronUp className="w-4 h-4 mr-1" />
            {t("collapse_all")}
          </Button>
        </div>
      </div>
      <div className="flex-1 overflow-auto p-4">
        <PlistView data={data} expanded={expandAll} />
      </div>
    </div>
  );
}

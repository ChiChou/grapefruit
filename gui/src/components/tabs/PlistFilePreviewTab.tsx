import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Status, useSession } from "@/context/SessionContext";
import { Loader2 } from "lucide-react";
import { PlistView } from "@/components/UnifiedPlistViewer";
import { type PlistValue } from "@/components/PlistTreeView";

export interface PlistFilePreviewTabParams {
  path: string;
}

export function PlistFilePreviewTab({
  params,
}: IDockviewPanelProps<PlistFilePreviewTabParams>) {
  const { api, status } = useSession();
  const { t } = useTranslation();
  const [xml, setXml] = useState<string>("");
  const [value, setValue] = useState<PlistValue | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fullPath = params?.path || "";

  const loadContent = useCallback(async () => {
    if (!api || status !== Status.Ready) return;

    setIsLoading(true);
    setError(null);

    try {
      const result = await api.fs.plist(fullPath);
      setXml(result.xml);
      setValue(result.value);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load plist");
      setXml("");
      setValue(null);
    } finally {
      setIsLoading(false);
    }
  }, [api, fullPath, status]);

  useEffect(() => {
    loadContent();
  }, [loadContent]);

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

  return (
    <PlistView
      xml={xml}
      value={value}
      filename={fullPath.split("/").pop() || "plist"}
    />
  );
}

import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";

import { PlistView } from "@/components/UnifiedPlistViewer";
import { type PlistValue } from "@/components/PlistTreeView";
import { useRpcQuery } from "@/lib/queries";

export interface PlistFilePreviewTabParams {
  path: string;
}

export function PlistFilePreviewTab({
  params,
}: IDockviewPanelProps<PlistFilePreviewTabParams>) {
  const { t } = useTranslation();

  const fullPath = params?.path || "";

  const {
    data,
    isLoading,
    error,
  } = useRpcQuery(
    ["plistPreview", fullPath],
    (api) => api.fs.plist(fullPath),
    { enabled: !!fullPath }
  );

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
        {(error as Error).message}
      </div>
    );
  }

  return (
    <PlistView
      xml={data?.xml ?? ""}
      value={(data?.value as PlistValue) ?? null}
      filename={fullPath.split("/").pop() || "plist"}
    />
  );
}

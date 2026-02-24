import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { t } from "i18next";

import HexView from "../shared/HexView";
import { usePlatformQuery } from "@/lib/queries";

export interface MemoryPreviewTabParams {
  address: string;
  size: number;
}

export function MemoryPreviewTab({
  params,
}: IDockviewPanelProps<MemoryPreviewTabParams>) {
  const address = params?.address;
  const size = params?.size;

  const {
    data: rawData,
    isLoading,
    error,
  } = usePlatformQuery<ArrayBuffer | null>(
    ["memory", address ?? "", String(size ?? 0)],
    (api) => api.memory.dump(address!, size!),
    { enabled: !!address && !!size },
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-red-500">
        {(error as Error).message}
      </div>
    );
  }

  if (!rawData) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No data
      </div>
    );
  }

  return <HexView data={new Uint8Array(rawData)} stride={16} />;
}

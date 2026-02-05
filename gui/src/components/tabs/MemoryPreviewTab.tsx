import type { IDockviewPanelProps } from "dockview";

import HexView from "../HexView";
import { useRpcQuery } from "@/lib/queries";

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
  } = useRpcQuery<ArrayBuffer>(
    ["memory", address ?? "", String(size ?? 0)],
    (api) => api.memory.dump(address!, size!),
    { enabled: !!address && !!size }
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        Loading...
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

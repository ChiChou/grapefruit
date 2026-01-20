import { useEffect, useState } from "react";
import type { IDockviewPanelProps } from "dockview";

import { Status, useSession } from "@/context/SessionContext";

import HexView from "../HexView";

export interface MemoryPreviewTabParams {
  address: string;
  size: number;
}

export function MemoryPreviewTab({
  params,
}: IDockviewPanelProps<MemoryPreviewTabParams>) {
  const { api, status } = useSession();

  const address = params?.address;
  const size = params?.size;

  const [loading, setLoading] = useState(false);
  const [data, setData] = useState<Uint8Array | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!api || status !== Status.Ready || !address || !size) return;

    const loadMemory = async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await api.memory.dump(address, size);
        const buffer = result as ArrayBuffer;
        setData(new Uint8Array(buffer));
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to read memory");
        setData(null);
      } finally {
        setLoading(false);
      }
    };

    loadMemory();
  }, [address, api, size, status]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-red-500">
        {error}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        No data
      </div>
    );
  }

  return <HexView data={data} stride={16} />;
}

import { useMemo } from "react";
import type { IDockviewPanelProps } from "dockview";
import { useQuery } from "@tanstack/react-query";
import { t } from "i18next";
import { Loader2 } from "lucide-react";

import { useSession } from "@/context/SessionContext";
import { useHBC } from "@/lib/use-hbc";
import { HermesViewer } from "@/components/shared/HermesViewer";

export interface HermesFileTabParams {
  path: string;
}

export function HermesFileTab({
  params,
}: IDockviewPanelProps<HermesFileTabParams>) {
  const { fruity, droid, device, pid } = useSession();
  const fullPath = params?.path || "";
  const filename = fullPath.split("/").pop() ?? "hermes";

  const {
    data: buffer,
    isLoading: fetching,
    error: fetchError,
  } = useQuery<ArrayBuffer, Error>({
    queryKey: ["hermesFile", device, pid, fullPath],
    queryFn: async () => {
      const url = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;
      const r = await fetch(url);
      if (!r.ok) throw new Error("Failed to download file");
      return r.arrayBuffer();
    },
    enabled: !!(fruity || droid) && !!fullPath,
  });

  const stableBuffer = useMemo(() => buffer ?? null, [buffer]);
  const { data, xrefs, isLoading, error, disassemble, decompile } =
    useHBC(stableBuffer);

  const loading = fetching || isLoading;
  const err = fetchError?.message || error;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (err) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {err}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <HermesViewer
      data={data}
      xrefs={xrefs}
      filename={filename}
      disassemble={disassemble}
      decompile={decompile}
    />
  );
}

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";

import { useSession } from "@/context/SessionContext";
import { useHBC } from "@/lib/use-hbc";
import { HermesViewer } from "@/components/shared/HermesViewer";

export interface HermesAnalysisParams {
  entryId: number;
  filename: string;
}

export function HermesAnalysisTab({
  params,
}: IDockviewPanelProps<HermesAnalysisParams>) {
  const { t } = useTranslation();
  const { device, identifier } = useSession();

  const [buffer, setBuffer] = useState<ArrayBuffer | null>(null);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [fetching, setFetching] = useState(true);

  useEffect(() => {
    if (!params?.entryId || !device || !identifier) return;

    let ignore = false;
    setFetching(true);
    setFetchError(null);

    (async () => {
      try {
        const res = await fetch(
          `/api/hermes/${device}/${identifier}/download/${params.entryId}`,
        );
        if (!res.ok) throw new Error("Failed to download Hermes bytecode");
        const buf = await res.arrayBuffer();
        if (!ignore) setBuffer(buf);
      } catch (e) {
        if (!ignore)
          setFetchError(e instanceof Error ? e.message : "Download failed");
      } finally {
        if (!ignore) setFetching(false);
      }
    })();

    return () => {
      ignore = true;
    };
  }, [params?.entryId, device, identifier]);

  const { data, xrefs, isLoading, error, disassemble, decompile } =
    useHBC(buffer);

  const loading = fetching || isLoading;
  const err = fetchError || error;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}...
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
      filename={params?.filename ?? "hermes"}
      buffer={buffer}
      disassemble={disassemble}
      decompile={decompile}
    />
  );
}

import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";

import { useR2File } from "@/lib/r2";
import { R2Viewer } from "@/components/shared/R2Viewer";
import { useSession } from "@/context/SessionContext";

export interface DexViewerParams {
  path?: string;
  apk?: string;
  entry?: string;
}

export function DexViewerTab({ params }: IDockviewPanelProps<DexViewerParams>) {
  const { t } = useTranslation();
  const { device, pid } = useSession();

  const [fileData, setFileData] = useState<ArrayBuffer | null>(null);
  const [fetching, setFetching] = useState(true);
  const [fetchError, setFetchError] = useState<string | null>(null);

  const fileName =
    params?.entry?.split("/").pop() ??
    params?.path?.split("/").pop() ??
    "classes.dex";

  useEffect(() => {
    if (!device || pid === undefined) return;
    if (!params?.path && !(params?.apk && params?.entry)) return;

    let ignore = false;
    setFetching(true);
    setFetchError(null);

    (async () => {
      try {
        let url: string;
        if (params?.apk && params?.entry) {
          url = `/api/apk-entry/${device}/${pid}?apk=${encodeURIComponent(params.apk)}&entry=${encodeURIComponent(params.entry)}`;
        } else {
          url = `/api/download/${device}/${pid}?path=${encodeURIComponent(params!.path!)}`;
        }
        const res = await fetch(url);
        if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
        const data = await res.arrayBuffer();
        if (!ignore) setFileData(data);
      } catch (e) {
        if (!ignore) setFetchError(e instanceof Error ? e.message : String(e));
      } finally {
        if (!ignore) setFetching(false);
      }
    })();

    return () => { ignore = true; };
  }, [device, pid, params?.path, params?.apk, params?.entry]);

  const {
    binType, arch, classes, functions, strings,
    isLoading, error, isReady,
    cmd, disassemble, cfg, xrefs, funcXrefs,
  } = useR2File({ data: fileData, name: fileName });

  const storageKey = `dex:${device}:${pid}:${params?.path ?? ""}:${params?.entry ?? ""}`;
  const loading = fetching || isLoading;

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        <span className="text-sm">{t("loading")}</span>
      </div>
    );
  }

  if (fetchError || error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive text-sm">
        {fetchError || error}
      </div>
    );
  }

  if (!isReady) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <R2Viewer
      binType={binType}
      arch={arch}
      classes={classes}
      functions={functions}
      strings={strings}
      cmd={cmd}
      disassemble={disassemble}
      cfg={cfg}
      xrefs={xrefs}
      funcXrefs={funcXrefs}
      storageKey={storageKey}
    />
  );
}

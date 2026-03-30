import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";

import { useDexR2Session } from "@/lib/use-dex-r2";
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

  const {
    classes,
    strings,
    isLoading,
    error,
    isReady,
    cmd,
    disassemble,
    cfg,
    xrefs,
    funcXrefs,
  } = useDexR2Session({
    deviceId: device,
    pid,
    path: params?.path,
    apk: params?.apk,
    entry: params?.entry,
  });

  const storageKey = `dex:${device}:${pid}:${params?.path ?? ""}:${params?.entry ?? ""}`;

  if (isLoading) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-3 text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin" />
        <span className="text-sm">{t("loading")}</span>
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

  if (!isReady) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_results")}
      </div>
    );
  }

  return (
    <R2Viewer
      binType="dex"
      arch="dalvik"
      classes={classes}
      functions={[]}
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

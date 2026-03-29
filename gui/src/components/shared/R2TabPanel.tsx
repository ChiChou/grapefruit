import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2 } from "lucide-react";
import { useR2File, filestore } from "@/lib/r2";
import { R2Viewer } from "./R2Viewer";

export function R2TabPanel({ fileId }: { fileId: string }) {
  const { t } = useTranslation();
  const [entry, setEntry] = useState<{ name: string; data: ArrayBuffer } | null>(null);
  const [fetching, setFetching] = useState(true);

  useEffect(() => {
    let ignore = false;
    setFetching(true);
    filestore.get(fileId).then((f) => {
      if (ignore) return;
      setEntry(f ? { name: f.name, data: f.data } : null);
      setFetching(false);
    });
    return () => { ignore = true; };
  }, [fileId]);

  const { binType, arch, classes, functions, strings, isLoading, error, isReady, disassemble, cfg, xrefs, funcXrefs } =
    useR2File({ data: entry?.data ?? null, name: entry?.name ?? "file" });

  const loading = fetching || isLoading;

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive text-sm">
        {error}
      </div>
    );
  }

  if (!isReady) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
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
      disassemble={disassemble}
      cfg={cfg}
      xrefs={xrefs}
      funcXrefs={funcXrefs}
    />
  );
}

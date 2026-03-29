import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2 } from "lucide-react";
import { useHBC } from "@/lib/use-hbc";
import { HermesViewer } from "./HermesViewer";
import * as store from "@/lib/hermes-store";

export function HermesTabPanel({ fileId }: { fileId: string }) {
  const { t } = useTranslation();
  const [entry, setEntry] = useState<store.StoredFile | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    let ignore = false;
    setLoading(true);
    store.get(fileId).then((f) => {
      if (ignore) return;
      setEntry(f ?? null);
      setLoading(false);
    });
    return () => { ignore = true; };
  }, [fileId]);

  const hbc = useHBC(entry?.data ?? null);

  if (loading || hbc.isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin mr-2" />
        {t("hermes_parsing")}
      </div>
    );
  }

  if (hbc.error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive text-sm">
        {hbc.error}
      </div>
    );
  }

  if (!hbc.data || !entry) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
        {t("no_results")}
      </div>
    );
  }

  return (
    <HermesViewer
      data={hbc.data}
      xrefs={hbc.xrefs}
      filename={entry.name}
      buffer={hbc.buffer}
      disassemble={hbc.disassemble}
      decompile={hbc.decompile}
    />
  );
}

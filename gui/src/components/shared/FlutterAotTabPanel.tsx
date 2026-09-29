import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Loader2, RefreshCw } from "lucide-react";

import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { FlutterAotViewer } from "./FlutterAotViewer";
import { analyze, disassemble, type FlutterAnalysis } from "@/lib/flutter-aot";
import { filestore } from "@/lib/r2";

export function FlutterAotTabPanel({ fileId }: { fileId: string }) {
  const { t } = useTranslation();
  const [entry, setEntry] = useState<{ name: string; data: ArrayBuffer } | null>(null);
  const [data, setData] = useState<FlutterAnalysis | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [fuzzy, setFuzzy] = useState(false);
  const [namePool, setNamePool] = useState(false);
  const [options, setOptions] = useState({ fuzzyStrings: false, namePool: false, run: 0 });

  useEffect(() => {
    let cancelled = false;
    filestore.get(fileId).then((file) => {
      if (!cancelled) setEntry(file ? { name: file.name, data: file.data } : null);
    });
    return () => { cancelled = true; };
  }, [fileId]);

  useEffect(() => {
    if (!entry) return;
    let cancelled = false;
    setLoading(true);
    setError(null);
    analyze(entry.name, entry.data, options)
      .then((value) => { if (!cancelled) setData(value); })
      .catch((reason: unknown) => {
        if (!cancelled) setError(reason instanceof Error ? reason.message : String(reason));
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, [entry, options]);

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex h-10 shrink-0 items-center gap-4 border-b bg-muted/20 px-3 text-xs">
        <label className="flex items-center gap-2">
          <Switch checked={namePool} onCheckedChange={setNamePool} />
          {t("flutter_name_pool")}
        </label>
        <label className="flex items-center gap-2">
          <Switch checked={fuzzy} onCheckedChange={setFuzzy} />
          {t("flutter_fuzzy_strings")}
        </label>
        <Button
          size="sm"
          variant="outline"
          className="ml-auto h-7"
          disabled={loading || !entry}
          onClick={() => setOptions((value) => ({ fuzzyStrings: fuzzy, namePool, run: value.run + 1 }))}
        >
          <RefreshCw className="h-3.5 w-3.5" />
          {t("flutter_reanalyze")}
        </Button>
      </div>
      <div className="min-h-0 flex-1">
        {loading && (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
            <Loader2 className="mr-2 h-5 w-5 animate-spin" />
            {t("flutter_analyzing")}
          </div>
        )}
        {!loading && error && <div className="flex h-full items-center justify-center p-6 text-sm text-destructive">{error}</div>}
        {!loading && !error && data && <FlutterAotViewer data={data} disassemble={disassemble} />}
        {!loading && !error && !data && <div className="flex h-full items-center justify-center text-sm text-muted-foreground">{t("no_results")}</div>}
      </div>
    </div>
  );
}

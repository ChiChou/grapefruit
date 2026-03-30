import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { useR2Session } from "@/lib/use-r2-session";
import { useR2 } from "@/context/R2Context";
import HexView from "@/components/shared/HexView";

const DUMP_SIZE = 512;

export function R2HexTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { cmd, isReady } = useR2Session();
  const { addr } = useR2();
  const [data, setData] = useState<Uint8Array | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastAddr, setLastAddr] = useState("");

  const load = useCallback(async () => {
    if (!isReady || !addr || addr === lastAddr) return;
    setLoading(true);
    setLastAddr(addr);
    try {
      const raw = await cmd(`pxj ${DUMP_SIZE} @ ${addr}`);
      const arr = JSON.parse(raw);
      if (Array.isArray(arr)) {
        setData(new Uint8Array(arr));
      } else {
        setData(null);
      }
    } catch {
      setData(null);
    } finally {
      setLoading(false);
    }
  }, [addr, isReady, cmd, lastAddr]);

  useEffect(() => { load(); }, [load]);

  if (!addr) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
        {t("r2_seek_to_hex")}
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />{t("loading")}
      </div>
    );
  }

  if (!data) {
    return (
      <div className="flex items-center justify-center h-full text-xs text-muted-foreground">
        {t("r2_no_hex")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="px-3 py-1 border-b text-xs text-muted-foreground font-mono">
        {addr} ({data.length} bytes)
      </div>
      <div className="flex-1 min-h-0">
        <HexView data={data} stride={16} />
      </div>
    </div>
  );
}

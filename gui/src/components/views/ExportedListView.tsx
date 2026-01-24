import { useCallback, useEffect, useState } from "react";
import { useSession } from "@/context/SessionContext";
import { SymbolsTableView } from "../SymbolsTableView";

import type { Symbol } from "../../../../agent/types/fruity/modules/symbol";

interface ExportedListViewProps {
  path: string;
}

export function ExportedListView({ path }: ExportedListViewProps) {
  const { api } = useSession();
  const [exported, setExported] = useState<Symbol[] | null>(null);
  const [loading, setLoading] = useState(false);

  const loadExported = useCallback(async () => {
    if (!api) return;
    if (exported !== null) return;

    setLoading(true);
    try {
      const result = await api.symbol.exports(path);
      setExported(result);
    } catch (err) {
      console.error("Failed to load exported symbols:", err);
      setExported([]);
    } finally {
      setLoading(false);
    }
  }, [api, path, exported]);

  useEffect(() => {
    loadExported();
  }, [loadExported]);

  return <SymbolsTableView symbols={exported} loading={loading} />;
}

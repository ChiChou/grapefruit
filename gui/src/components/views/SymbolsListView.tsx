import { useCallback, useEffect, useState } from "react";
import { useSession } from "@/context/SessionContext";
import { SymbolsTableView } from "../SymbolsTableView";

import type { Symbol } from "../../../../agent/types/fruity/modules/symbol";

interface SymbolsListViewProps {
  path: string;
}

export function SymbolsListView({ path }: SymbolsListViewProps) {
  const { api } = useSession();
  const [symbols, setSymbols] = useState<Symbol[] | null>(null);
  const [loading, setLoading] = useState(false);

  const loadSymbols = useCallback(async () => {
    if (!api) return;
    if (symbols !== null) return;

    setLoading(true);
    try {
      const result = await api.symbol.symbols(path);
      setSymbols(result);
    } catch (err) {
      console.error("Failed to load symbols:", err);
      setSymbols([]);
    } finally {
      setLoading(false);
    }
  }, [api, path, symbols]);

  useEffect(() => {
    loadSymbols();
  }, [loadSymbols]);

  return <SymbolsTableView symbols={symbols} loading={loading} />;
}

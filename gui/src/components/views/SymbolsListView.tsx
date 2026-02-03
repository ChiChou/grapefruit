import { SymbolsTableView } from "../SymbolsTableView";
import { useRpcQuery } from "@/lib/queries";

import type { Symbol } from "../../../../agent/types/fruity/modules/symbol";

interface SymbolsListViewProps {
  path: string;
}

export function SymbolsListView({ path }: SymbolsListViewProps) {
  const { data: symbols, isLoading: loading } = useRpcQuery<Symbol[]>(
    ["symbols", path],
    (api) => api.symbol.symbols(path)
  );

  return <SymbolsTableView symbols={symbols ?? null} loading={loading} />;
}

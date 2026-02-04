import { SymbolsTableView } from "../SymbolsTableView";
import { useRpcQuery } from "@/lib/queries";


interface SymbolsListViewProps {
  path: string;
}

export function SymbolsListView({ path }: SymbolsListViewProps) {
  const { data: symbols, isLoading: loading } = useRpcQuery(
    ["symbols", path],
    (api) => api.symbol.symbols(path)
  );

  return <SymbolsTableView symbols={symbols ?? null} loading={loading} />;
}

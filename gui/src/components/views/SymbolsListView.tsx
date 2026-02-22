import { SymbolsTableView } from "../shared/SymbolsTableView";
import { usePlatformQuery } from "@/lib/queries";


interface SymbolsListViewProps {
  path: string;
}

export function SymbolsListView({ path }: SymbolsListViewProps) {
  const { data: symbols, isLoading: loading } = usePlatformQuery(
    ["symbols", path],
    (api) => api.symbol.symbols(path)
  );

  return <SymbolsTableView symbols={symbols ?? null} loading={loading} />;
}

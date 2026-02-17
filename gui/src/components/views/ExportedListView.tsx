import { SymbolsTableView } from "../SymbolsTableView";
import { usePlatformRpcQuery } from "@/lib/queries";


interface ExportedListViewProps {
  path: string;
}

export function ExportedListView({ path }: ExportedListViewProps) {
  const { data: exported, isLoading: loading } = usePlatformRpcQuery(
    ["exports", path],
    (api) => api.symbol.exports(path)
  );

  return <SymbolsTableView symbols={exported ?? null} loading={loading} />;
}

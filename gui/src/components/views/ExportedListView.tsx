import { SymbolsTableView } from "../shared/SymbolsTableView";
import { usePlatformQuery } from "@/lib/queries";


interface ExportedListViewProps {
  path: string;
}

export function ExportedListView({ path }: ExportedListViewProps) {
  const { data: exported, isLoading: loading } = usePlatformQuery(
    ["exports", path],
    (api) => api.symbol.exports(path)
  );

  return <SymbolsTableView symbols={exported ?? null} loading={loading} />;
}

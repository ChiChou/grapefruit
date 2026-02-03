import { SymbolsTableView } from "../SymbolsTableView";
import { useRpcQuery } from "@/lib/queries";

import type { Symbol } from "../../../../agent/types/fruity/modules/symbol";

interface ExportedListViewProps {
  path: string;
}

export function ExportedListView({ path }: ExportedListViewProps) {
  const { data: exported, isLoading: loading } = useRpcQuery<Symbol[]>(
    ["exports", path],
    (api) => api.symbol.exports(path)
  );

  return <SymbolsTableView symbols={exported ?? null} loading={loading} />;
}

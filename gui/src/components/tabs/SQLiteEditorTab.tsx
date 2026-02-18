import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";

import type { DumpResult } from "@agent/common/sqlite";

import { Platform, useSession } from "@/context/SessionContext";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { useQuery, useMutation } from "@tanstack/react-query";

export interface SQLiteEditorTabParams {
  path: string;
}

export function SQLiteEditorTab({
  params,
}: IDockviewPanelProps<SQLiteEditorTabParams>) {
  const { t } = useTranslation();
  const { fruity, droid, platform } = useSession();
  const sqlite =
    (platform === Platform.Droid ? droid?.sqlite : fruity?.sqlite) ?? null;

  const [filteredTables, setFilteredTables] = useState<string[]>([]);
  const [tableSearch, setTableSearch] = useState("");
  const [dumpResult, setDumpResult] = useState<DumpResult | null>(null);

  const fullPath = params?.path || "";

  // Fetch tables
  const {
    data: tables = [],
    isLoading,
    error,
  } = useQuery<string[], Error>({
    queryKey: ["sqliteTables", fullPath],
    queryFn: () => sqlite!.tables(fullPath),
    enabled: !!sqlite && !!fullPath,
    staleTime: 0,
    gcTime: 0,
  });

  // Mutation for loading table data (dump)
  const dumpMutation = useMutation<DumpResult, Error, { table: string }>({
    mutationFn: ({ table }) => sqlite!.dump(fullPath, table),
  });

  useEffect(() => {
    setFilteredTables(tables);
  }, [tables]);

  const loadTableData = async (tableName: string) => {
    try {
      const result = await dumpMutation.mutateAsync({ table: tableName });
      setDumpResult(result);
    } catch (err) {
      console.error("Failed to load table data:", err);
    }
  };

  useEffect(() => {
    if (tableSearch.trim() === "") {
      setFilteredTables(tables);
    } else {
      const lower = tableSearch.toLowerCase();
      setFilteredTables(tables.filter((t) => t.toLowerCase().includes(lower)));
    }
  }, [tableSearch, tables]);

  const isLoadingTable = dumpMutation.isPending;

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {(error as Error).message}
      </div>
    );
  }

  return (
    <ResizablePanelGroup
      orientation="horizontal"
      autoSaveId="sqlite-editor"
      className="h-full"
    >
      <ResizablePanel defaultSize="30%" minSize="20%">
        <div className="h-full flex flex-col border-r">
          <div className="p-2 border-b">
            <Input
              placeholder={t("search")}
              value={tableSearch}
              onChange={(e) => setTableSearch(e.target.value)}
            />
          </div>
          <div className="flex-1 overflow-auto">
            {filteredTables.map((table) => (
              <button
                key={table}
                onClick={() => loadTableData(table)}
                disabled={isLoadingTable}
                className="w-full px-3 py-2 text-left hover:bg-accent hover:text-accent-foreground text-sm truncate disabled:opacity-50"
              >
                {table}
              </button>
            ))}
          </div>
        </div>
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel defaultSize="70%" minSize="30%">
        <div className="h-full overflow-auto">
          {dumpResult ? (
            <Table>
              <TableHeader>
                <TableRow>
                  {dumpResult.header.map((h, i) => (
                    <TableHead key={i}>
                      <div className="flex flex-col">
                        <span>{h.name}</span>
                        <span className="text-xs text-muted-foreground">
                          {h.type}
                        </span>
                      </div>
                    </TableHead>
                  ))}
                </TableRow>
              </TableHeader>
              <TableBody>
                {dumpResult.data.map((row, rowIndex) => (
                  <TableRow key={rowIndex}>
                    {dumpResult.header.map((_, colIndex) => (
                      <TableCell key={colIndex}>
                        {row[colIndex] === null ||
                        row[colIndex] === undefined
                          ? "NULL"
                          : String(row[colIndex])}
                      </TableCell>
                    ))}
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          ) : (
            <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
              {t("select_table_or_execute")}
            </div>
          )}
        </div>
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

import { useEffect, useState, useMemo } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import Editor from "@monaco-editor/react";
import { Play, Loader2 } from "lucide-react";

import type { DumpResult } from "@agent/common/sqlite";

import { Platform, useSession } from "@/context/SessionContext";
import { useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";
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

interface QueryResult {
  header: string[];
  data: unknown[][];
}

export function SQLiteEditorTab({
  params,
}: IDockviewPanelProps<SQLiteEditorTabParams>) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { fruity, droid, platform } = useSession();
  const sqlite =
    (platform === Platform.Droid ? droid?.sqlite : fruity?.sqlite) ?? null;

  const [filteredTables, setFilteredTables] = useState<string[]>([]);
  const [tableSearch, setTableSearch] = useState("");
  const [sql, setSQL] = useState("SELECT * FROM ");
  const [dumpResult, setDumpResult] = useState<DumpResult | null>(null);
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null);
  const [executeError, setExecuteError] = useState<string | null>(null);

  const fullPath = params?.path || "";

  // Open database handle
  const {
    data: dbHandle,
    isLoading: isOpeningDb,
    error: openError,
  } = useQuery<number, Error>({
    queryKey: ["sqliteOpen", fullPath],
    queryFn: () => sqlite!.open(fullPath),
    enabled: !!sqlite && !!fullPath,
    staleTime: 0,
    gcTime: 0,
  });

  // Close database handle on unmount
  useEffect(() => {
    return () => {
      if (dbHandle !== undefined && sqlite) {
        sqlite.close(dbHandle).catch(console.error);
      }
    };
  }, [dbHandle, sqlite]);

  // Fetch tables
  const {
    data: tables = [],
    isLoading: isLoadingTables,
    error: tablesError,
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

  // Mutation for executing arbitrary SQL
  const queryMutation = useMutation<
    unknown[][],
    Error,
    { handle: number; sql: string }
  >({
    mutationFn: ({ handle, sql }) => sqlite!.query(handle, sql),
  });

  useEffect(() => {
    setFilteredTables(tables);
  }, [tables]);

  const loadTableData = async (tableName: string) => {
    try {
      const result = await dumpMutation.mutateAsync({ table: tableName });
      setDumpResult(result);
      setQueryResult(null);
      setExecuteError(null);
      setSQL(`SELECT * FROM "${tableName}" LIMIT 100;`);
    } catch (err) {
      console.error("Failed to load table data:", err);
    }
  };

  const executeSQL = async () => {
    if (dbHandle === undefined || !sql.trim()) return;

    setExecuteError(null);

    try {
      const data = await queryMutation.mutateAsync({ handle: dbHandle, sql });

      // Generate column headers from first row
      const columnCount = data.length > 0 ? data[0].length : 0;
      const header: string[] = [];
      for (let i = 0; i < columnCount; i++) {
        header.push(String(i));
      }

      setQueryResult({ header, data });
      setDumpResult(null);
    } catch (err) {
      setExecuteError(err instanceof Error ? err.message : String(err));
      setQueryResult(null);
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

  const isLoading = isOpeningDb || isLoadingTables;
  const error = openError || tablesError;
  const isExecuting = queryMutation.isPending;
  const isLoadingTable = dumpMutation.isPending;

  // Determine if execute button should be disabled
  const executeDisabled = useMemo(
    () => isExecuting || !sql.trim() || dbHandle === undefined,
    [isExecuting, sql, dbHandle],
  );

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
      <ResizablePanel defaultSize={30} minSize={20}>
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
      <ResizablePanel defaultSize={70} minSize={30}>
        <ResizablePanelGroup orientation="vertical" className="h-full">
          <ResizablePanel defaultSize={50} minSize={20}>
            <div className="h-full flex flex-col">
              <div className="flex items-center gap-2 p-2 border-b">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={executeSQL}
                  disabled={executeDisabled}
                >
                  {isExecuting ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4 mr-2" />
                  )}
                  {t("execute")}
                </Button>
              </div>
              <div className="flex-1">
                <Editor
                  language="sql"
                  value={sql}
                  theme={theme === "dark" ? "vs-dark" : "light"}
                  onChange={(value) => setSQL(value || "")}
                  options={{
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    fontSize: 13,
                  }}
                />
              </div>
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          <ResizablePanel defaultSize={50} minSize={20}>
            <div className="h-full overflow-auto">
              {executeError ? (
                <div className="flex items-center justify-center h-full text-destructive text-sm p-4">
                  <pre className="whitespace-pre-wrap">{executeError}</pre>
                </div>
              ) : queryResult ? (
                <div className="flex flex-col h-full">
                  <div className="p-2 border-b text-xs text-muted-foreground">
                    {t("rows_returned", { count: queryResult.data.length })}
                  </div>
                  <div className="flex-1 overflow-auto">
                    {queryResult.data.length > 0 ? (
                      <Table>
                        <TableHeader>
                          <TableRow>
                            {queryResult.header.map((name, i) => (
                              <TableHead key={i}>{name}</TableHead>
                            ))}
                          </TableRow>
                        </TableHeader>
                        <TableBody>
                          {queryResult.data.map((row, rowIndex) => (
                            <TableRow key={rowIndex}>
                              {queryResult.header.map((_, colIndex) => (
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
                        {t("query_executed_no_results")}
                      </div>
                    )}
                  </div>
                </div>
              ) : dumpResult ? (
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
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

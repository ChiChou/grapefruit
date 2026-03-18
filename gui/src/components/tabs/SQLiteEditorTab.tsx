import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, Play } from "lucide-react";
import Editor from "@monaco-editor/react";

import type { DumpResult, QueryResult } from "@agent/common/sqlite";

import { Platform, useSession } from "@/context/SessionContext";
import { useTheme } from "@/components/providers/ThemeProvider";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
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

type DataView =
  | { kind: "dump"; result: DumpResult }
  | { kind: "query"; result: QueryResult }
  | null;

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
  const [dataView, setDataView] = useState<DataView>(null);
  const [sqlCode, setSqlCode] = useState(
    () => localStorage.getItem("sqlite-editor-sql") ?? "SELECT 1",
  );
  const [queryError, setQueryError] = useState<string | null>(null);

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

  // Mutation for arbitrary SQL query
  const queryMutation = useMutation<QueryResult, Error, { sql: string }>({
    mutationFn: ({ sql }) => sqlite!.query(fullPath, sql),
  });

  const loadTableData = async (tableName: string) => {
    const sql = `SELECT * FROM "${tableName.replace(/"/g, '""')}" LIMIT 500`;
    setSqlCode(sql);
    localStorage.setItem("sqlite-editor-sql", sql);
    setQueryError(null);
    try {
      const result = await dumpMutation.mutateAsync({ table: tableName });
      setDataView({ kind: "dump", result });
    } catch (err) {
      console.error("Failed to load table data:", err);
    }
  };

  const executeQuery = async () => {
    const sql = sqlCode.trim();
    if (!sql) return;
    setQueryError(null);
    try {
      const result = await queryMutation.mutateAsync({ sql });
      setDataView({ kind: "query", result });
    } catch (err) {
      setQueryError((err as Error).message);
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

  const isLoadingTable = dumpMutation.isPending || queryMutation.isPending;

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

  // Render the data table for both dump and query results
  const renderDataTable = () => {
    if (!dataView) {
      return (
        <div className="flex items-center justify-center h-full text-muted-foreground text-sm">
          {t("select_table_or_execute")}
        </div>
      );
    }

    if (dataView.kind === "dump") {
      const { result } = dataView;
      return (
        <Table>
          <TableHeader>
            <TableRow>
              {result.header.map((h, i) => (
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
            {result.data.map((row, rowIndex) => (
              <TableRow key={rowIndex}>
                {result.header.map((_, colIndex) => (
                  <TableCell key={colIndex}>
                    {row[colIndex] === null || row[colIndex] === undefined
                      ? "NULL"
                      : String(row[colIndex])}
                  </TableCell>
                ))}
              </TableRow>
            ))}
          </TableBody>
        </Table>
      );
    }

    // query result
    const { result } = dataView;
    return (
      <Table>
        <TableHeader>
          <TableRow>
            {result.columns.map((col, i) => (
              <TableHead key={i}>
                <div className="flex flex-col">
                  <span>{col}</span>
                  {result.types[i] && (
                    <span className="text-xs text-muted-foreground">
                      {result.types[i]}
                    </span>
                  )}
                </div>
              </TableHead>
            ))}
          </TableRow>
        </TableHeader>
        <TableBody>
          {result.data.map((row, rowIndex) => (
            <TableRow key={rowIndex}>
              {result.columns.map((_, colIndex) => (
                <TableCell key={colIndex}>
                  {row[colIndex] === null || row[colIndex] === undefined
                    ? "NULL"
                    : String(row[colIndex])}
                </TableCell>
              ))}
            </TableRow>
          ))}
        </TableBody>
      </Table>
    );
  };

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
        <ResizablePanelGroup
          orientation="vertical"
          autoSaveId="sqlite-editor-vertical"
          className="h-full"
        >
          {/* SQL Editor */}
          <ResizablePanel defaultSize="30%" minSize="10%">
            <div className="h-full flex flex-col border-b">
              <div className="flex items-center justify-between px-2 py-1 border-b">
                <span className="text-xs text-muted-foreground font-medium">
                  SQL
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={executeQuery}
                  disabled={isLoadingTable || !sqlCode.trim()}
                >
                  {queryMutation.isPending ? (
                    <Loader2 className="w-3 h-3 animate-spin mr-1" />
                  ) : (
                    <Play className="w-3 h-3 mr-1" />
                  )}
                  {t("run")}
                </Button>
              </div>
              <div className="flex-1 min-h-0">
                <Editor
                  height="100%"
                  language="sql"
                  value={sqlCode}
                  onChange={(value) => {
                    const code = value || "";
                    setSqlCode(code);
                    localStorage.setItem("sqlite-editor-sql", code);
                  }}
                  theme={theme === "dark" ? "vs-dark" : "light"}
                  options={{
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    fontSize: 13,
                    lineNumbers: "on",
                    folding: false,
                    automaticLayout: true,
                    tabSize: 2,
                    wordWrap: "on",
                  }}
                />
              </div>
            </div>
          </ResizablePanel>
          <ResizableHandle withHandle />
          {/* Results */}
          <ResizablePanel defaultSize="70%" minSize="20%">
            <div className="h-full overflow-auto">
              {queryError ? (
                <div className="p-3 text-sm text-destructive whitespace-pre-wrap font-mono">
                  {queryError}
                </div>
              ) : (
                renderDataTable()
              )}
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

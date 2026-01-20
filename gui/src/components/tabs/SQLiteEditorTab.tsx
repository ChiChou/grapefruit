import { useCallback, useEffect, useState } from "react";
import type { IDockviewPanelProps } from "dockview";
import Editor from "@monaco-editor/react";

import type { DumpResult } from "../../../../agent/types/common/sqlite";

import { useSession, ConnectionStatus } from "@/context/SessionContext";
import { useTheme } from "@/components/theme-provider";
import { Button } from "@/components/ui/button";
import { Play } from "lucide-react";
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

export interface SQLiteEditorTabParams {
  path: string;
}

export function SQLiteEditorTab({
  params,
}: IDockviewPanelProps<SQLiteEditorTabParams>) {
  const { theme } = useTheme();
  const { api, status } = useSession();

  const [tables, setTables] = useState<string[]>([]);
  const [filteredTables, setFilteredTables] = useState<string[]>([]);
  const [tableSearch, setTableSearch] = useState("");
  const [loading, setLoading] = useState(true);
  const [sql, setSQL] = useState("SELECT * FROM ");
  const [dumpResult, setDumpResult] = useState<DumpResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  const fullPath = params?.path || "";
  const apiReady = status === ConnectionStatus.Ready && !!api;

  const loadContent = useCallback(async () => {
    if (!apiReady || !fullPath) return;

    setLoading(true);
    setError(null);

    try {
      const tableList = await api.sqlite.tables(fullPath);
      setTables(tableList);
      setFilteredTables(tableList);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load file");
    } finally {
      setLoading(false);
    }
  }, [api, apiReady, fullPath]);

  const loadTableData = useCallback(
    async (tableName: string) => {
      if (!apiReady || !fullPath) return;

      try {
        const result = await api.sqlite.dump(fullPath, tableName);
        setDumpResult(result);
        setSQL(`SELECT * FROM "${tableName}" LIMIT 100;`);
      } catch (err) {
        setError(
          err instanceof Error ? err.message : "Failed to load table data",
        );
      }
    },
    [api, apiReady, fullPath],
  );

  useEffect(() => {
    loadContent();
  }, [loadContent]);

  useEffect(() => {
    if (tableSearch.trim() === "") {
      setFilteredTables(tables);
    } else {
      const lower = tableSearch.toLowerCase();
      setFilteredTables(tables.filter((t) => t.toLowerCase().includes(lower)));
    }
  }, [tableSearch, tables]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        Loading...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {error}
      </div>
    );
  }

  return (
    <ResizablePanelGroup
      direction="horizontal"
      autoSaveId="sqlite-editor"
      className="h-full"
    >
      <ResizablePanel defaultSize={30} minSize={20}>
        <div className="h-full flex flex-col border-r">
          <div className="p-2 border-b">
            <Input
              placeholder="Search tables..."
              value={tableSearch}
              onChange={(e) => setTableSearch(e.target.value)}
            />
          </div>
          <div className="flex-1 overflow-auto">
            {filteredTables.map((table) => (
              <button
                key={table}
                onClick={() => loadTableData(table)}
                className="w-full px-3 py-2 text-left hover:bg-accent hover:text-accent-foreground text-sm truncate"
              >
                {table}
              </button>
            ))}
          </div>
        </div>
      </ResizablePanel>
      <ResizableHandle withHandle />
      <ResizablePanel defaultSize={70} minSize={30}>
        <ResizablePanelGroup direction="vertical" className="h-full">
          <ResizablePanel defaultSize={50} minSize={20}>
            <div className="h-full flex flex-col">
              <div className="flex items-center gap-2 p-2 border-b">
                <Button variant="outline" size="sm">
                  <Play className="h-4 w-4 mr-2" />
                  Execute
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
                  Select a table to view data
                </div>
              )}
            </div>
          </ResizablePanel>
        </ResizablePanelGroup>
      </ResizablePanel>
    </ResizablePanelGroup>
  );
}

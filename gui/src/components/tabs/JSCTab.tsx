import { useState } from "react";
import { useTranslation } from "react-i18next";
import {
  RefreshCw,
  Play,
  ChevronDown,
  ChevronRight,
  FileCode,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Textarea } from "@/components/ui/textarea";
import { useRpcQuery, useRpcMutation } from "@/lib/queries";

interface JSCEntry {
  handle: string;
  description: string;
}

export function JSCTab() {
  const { t } = useTranslation();
  const [expandedHandle, setExpandedHandle] = useState<string | null>(null);
  const [jsCode, setJsCode] = useState("1 + 1");
  const [jsResult, setJsResult] = useState<string | null>(null);
  const [dumpResult, setDumpResult] = useState<Record<string, unknown> | null>(null);

  const {
    data: contexts,
    isLoading,
    refetch,
  } = useRpcQuery<Record<string, string>>(["jsc"], (api) => api.jsc.list());

  const runMutation = useRpcMutation<string, { handle: string; js: string }>(
    (api, { handle, js }) => api.jsc.run(handle, js)
  );

  const dumpMutation = useRpcMutation<Record<string, unknown>, { handle: string }>(
    (api, { handle }) => api.jsc.dump(handle)
  );

  const entries: JSCEntry[] = [];
  if (contexts) {
    for (const [handle, description] of Object.entries(contexts)) {
      entries.push({ handle, description });
    }
  }

  const toggleExpand = async (handle: string) => {
    if (expandedHandle === handle) {
      setExpandedHandle(null);
      setJsResult(null);
      setDumpResult(null);
    } else {
      setExpandedHandle(handle);
      setJsResult(null);
      setDumpResult(null);
    }
  };

  const executeJs = async (handle: string) => {
    try {
      const result = await runMutation.mutateAsync({ handle, js: jsCode });
      setJsResult(result);
    } catch (e) {
      setJsResult(`Error: ${(e as Error).message}`);
    }
  };

  const doDump = async (handle: string) => {
    try {
      const result = await dumpMutation.mutateAsync({ handle });
      setDumpResult(result);
    } catch (e) {
      console.error("Failed to dump:", e);
    }
  };

  return (
    <div className="flex flex-col h-full">
      <div className="flex items-center gap-2 p-2 border-b">
        <Button
          variant="outline"
          size="sm"
          onClick={() => refetch()}
          disabled={isLoading}
        >
          <RefreshCw className={`w-4 h-4 mr-2 ${isLoading ? "animate-spin" : ""}`} />
          {t("reload")}
        </Button>
        <span className="text-sm text-muted-foreground ml-auto">
          {entries.length} JSContext(s)
        </span>
      </div>
      <div className="flex-1 overflow-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-gray-500">
            <Spinner className="w-5 h-5" />
            <span>{t("loading")}...</span>
          </div>
        ) : entries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            No JSContext found
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead className="w-8"></TableHead>
                <TableHead className="w-40">Handle</TableHead>
                <TableHead>Description</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {entries.map((entry) => (
                <>
                  <TableRow
                    key={entry.handle}
                    className="cursor-pointer"
                    onClick={() => toggleExpand(entry.handle)}
                  >
                    <TableCell>
                      {expandedHandle === entry.handle ? (
                        <ChevronDown className="w-4 h-4" />
                      ) : (
                        <ChevronRight className="w-4 h-4" />
                      )}
                    </TableCell>
                    <TableCell className="font-mono text-xs">
                      {entry.handle}
                    </TableCell>
                    <TableCell className="font-mono text-sm truncate max-w-[400px]" title={entry.description}>
                      {entry.description}
                    </TableCell>
                  </TableRow>
                  {expandedHandle === entry.handle && (
                    <TableRow key={`detail-${entry.handle}`}>
                      <TableCell
                        colSpan={3}
                        className="bg-gray-50 dark:bg-gray-900 p-4"
                      >
                        <div className="space-y-4">
                          <div>
                            <div className="text-sm font-medium mb-2">Execute JavaScript</div>
                            <Textarea
                              placeholder="1 + 1"
                              value={jsCode}
                              onChange={(e) => setJsCode(e.target.value)}
                              className="font-mono text-sm mb-2"
                              rows={3}
                              onClick={(e) => e.stopPropagation()}
                            />
                            <div className="flex gap-2">
                              <Button
                                size="sm"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  executeJs(entry.handle);
                                }}
                                disabled={runMutation.isPending}
                              >
                                <Play className="w-4 h-4 mr-2" />
                                Run
                              </Button>
                              <Button
                                size="sm"
                                variant="outline"
                                onClick={(e) => {
                                  e.stopPropagation();
                                  doDump(entry.handle);
                                }}
                                disabled={dumpMutation.isPending}
                              >
                                <FileCode className="w-4 h-4 mr-2" />
                                Dump Global Objects
                              </Button>
                            </div>
                            {jsResult !== null && (
                              <div className="mt-2">
                                <div className="text-sm text-muted-foreground mb-1">Result:</div>
                                <pre className="font-mono text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded overflow-x-auto max-h-40">
                                  {jsResult}
                                </pre>
                              </div>
                            )}
                          </div>
                          {dumpResult && (
                            <div>
                              <div className="text-sm font-medium mb-2">Global Objects</div>
                              <div className="max-h-80 overflow-auto">
                                <Table>
                                  <TableHeader>
                                    <TableRow>
                                      <TableHead className="w-40">Name</TableHead>
                                      <TableHead>Value</TableHead>
                                    </TableRow>
                                  </TableHeader>
                                  <TableBody>
                                    {Object.entries(dumpResult).map(([key, value]) => (
                                      <TableRow key={key}>
                                        <TableCell className="font-mono text-xs font-medium">
                                          {key}
                                        </TableCell>
                                        <TableCell className="font-mono text-xs">
                                          <pre className="whitespace-pre-wrap max-w-[400px] overflow-hidden">
                                            {typeof value === "object"
                                              ? JSON.stringify(value, null, 2)
                                              : String(value)}
                                          </pre>
                                        </TableCell>
                                      </TableRow>
                                    ))}
                                  </TableBody>
                                </Table>
                              </div>
                            </div>
                          )}
                        </div>
                      </TableCell>
                    </TableRow>
                  )}
                </>
              ))}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}

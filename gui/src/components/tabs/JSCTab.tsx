import { useState, useRef } from "react";
import { useTranslation } from "react-i18next";
import Editor, { type Monaco } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import {
  RefreshCw,
  Play,
  ChevronRight,
  ChevronDown,
  Braces,
  Brackets,
  Hash,
  Type,
  ToggleLeft,
  Box,
  FileCode,
  Terminal,
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
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { useTheme } from "@/components/theme-provider";
import { useRpcQuery, useRpcMutation } from "@/lib/queries";

// Configure Monaco for JSC JavaScript (no DOM, just ESNext)
function handleEditorWillMount(monaco: Monaco) {
  monaco.languages.typescript.javascriptDefaults.setCompilerOptions({
    target: monaco.languages.typescript.ScriptTarget.ESNext,
    allowNonTsExtensions: true,
    lib: ["esnext"],
  });

  monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
    noSemanticValidation: false,
    noSyntaxValidation: false,
  });
}

interface JSCEntry {
  handle: string;
  description: string;
}

function ValueIcon({ value }: { value: unknown }) {
  if (value === null || value === undefined) {
    return <span className="text-muted-foreground">null</span>;
  }
  if (typeof value === "boolean") {
    return <ToggleLeft className="w-3 h-3 text-purple-500" />;
  }
  if (typeof value === "number") {
    return <Hash className="w-3 h-3 text-amber-500" />;
  }
  if (typeof value === "string") {
    return <Type className="w-3 h-3 text-green-500" />;
  }
  if (Array.isArray(value)) {
    return <Brackets className="w-3 h-3 text-orange-500" />;
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (obj.type === "function" || obj.type === "block") {
      return <FileCode className="w-3 h-3 text-yellow-500" />;
    }
    if (obj.type === "instance" || obj.type === "class") {
      return <Box className="w-3 h-3 text-pink-500" />;
    }
    return <Braces className="w-3 h-3 text-cyan-500" />;
  }
  return null;
}

function ValuePreview({ value }: { value: unknown }) {
  if (value === null)
    return <span className="text-muted-foreground">null</span>;
  if (value === undefined)
    return <span className="text-muted-foreground">undefined</span>;
  if (typeof value === "boolean") {
    return (
      <span className="text-purple-600 dark:text-purple-400">
        {value ? "true" : "false"}
      </span>
    );
  }
  if (typeof value === "number") {
    return <span className="text-amber-600 dark:text-amber-400">{value}</span>;
  }
  if (typeof value === "string") {
    return (
      <span className="text-green-600 dark:text-green-400 break-all">
        "{value}"
      </span>
    );
  }
  if (Array.isArray(value)) {
    return (
      <span className="text-orange-600 dark:text-orange-400">
        Array[{value.length}]
      </span>
    );
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    if (obj.type === "function") {
      return (
        <span className="text-yellow-600 dark:text-yellow-400">ƒ function</span>
      );
    }
    if (obj.type === "block") {
      return (
        <span className="text-yellow-600 dark:text-yellow-400">
          ƒ block @ {String(obj.handle)}
        </span>
      );
    }
    if (obj.type === "instance") {
      return (
        <span className="text-pink-600 dark:text-pink-400">
          {String(obj.clazz)} @ {String(obj.handle)}
        </span>
      );
    }
    if (obj.type === "class") {
      return (
        <span className="text-pink-600 dark:text-pink-400">
          class {String(obj.clazz)}
        </span>
      );
    }
    if (obj.type === "array") {
      return (
        <span className="text-orange-600 dark:text-orange-400">
          NSArray[{String(obj.size)}]
        </span>
      );
    }
    if (obj.type === "dict") {
      return (
        <span className="text-cyan-600 dark:text-cyan-400">
          NSDictionary[{String(obj.size)}]
        </span>
      );
    }
    const keys = Object.keys(obj);
    return (
      <span className="text-cyan-600 dark:text-cyan-400">
        {`{${keys.length} keys}`}
      </span>
    );
  }
  return <span>{String(value)}</span>;
}

function TreeNode({
  name,
  value,
  depth = 0,
}: {
  name: string;
  value: unknown;
  depth?: number;
}) {
  const [expanded, setExpanded] = useState(false);
  const isExpandable =
    value !== null &&
    typeof value === "object" &&
    Object.keys(value as object).length > 0;

  const obj = value as Record<string, unknown> | null;
  const childEntries = isExpandable ? Object.entries(obj!) : [];

  return (
    <div className="font-mono text-xs">
      <div
        className={`flex items-center gap-1 py-0.5 px-1 hover:bg-accent rounded ${
          isExpandable ? "cursor-pointer" : ""
        }`}
        style={{ paddingLeft: `${depth * 16 + 4}px` }}
        onClick={() => isExpandable && setExpanded(!expanded)}
      >
        {isExpandable ? (
          expanded ? (
            <ChevronDown className="w-3 h-3 shrink-0" />
          ) : (
            <ChevronRight className="w-3 h-3 shrink-0" />
          )
        ) : (
          <span className="w-3" />
        )}
        <ValueIcon value={value} />
        <span className="font-medium text-foreground">{name}</span>
        <span className="text-muted-foreground">:</span>
        <span className="ml-1 truncate">
          <ValuePreview value={value} />
        </span>
      </div>
      {expanded && isExpandable && (
        <div>
          {childEntries.map(([key, val]) => (
            <TreeNode key={key} name={key} value={val} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

function DumpView({
  data,
  t,
}: {
  data: Record<string, unknown>;
  t: (key: string, options?: Record<string, unknown>) => string;
}) {
  const entries = Object.entries(data);
  const [filter, setFilter] = useState("");

  const filteredEntries = filter
    ? entries.filter(([key]) =>
        key.toLowerCase().includes(filter.toLowerCase()),
      )
    : entries;

  return (
    <div className="flex flex-col h-full">
      <div className="p-2 border-b">
        <input
          type="text"
          placeholder={t("filter_by_name")}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          className="w-full px-2 py-1 text-sm border rounded bg-background"
        />
      </div>
      <div className="flex-1 overflow-auto p-2">
        {filteredEntries.length === 0 ? (
          <div className="text-center text-muted-foreground py-4">
            {filter ? t("no_matching_entries") : t("no_global_objects")}
          </div>
        ) : (
          filteredEntries.map(([key, value]) => (
            <TreeNode key={key} name={key} value={value} />
          ))
        )}
      </div>
      <div className="p-2 border-t text-xs text-muted-foreground">
        {t("entries_count", {
          filtered: filteredEntries.length,
          total: entries.length,
        })}
      </div>
    </div>
  );
}

export function JSCTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [selectedHandle, setSelectedHandle] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState("dump");
  const [jsCode, setJsCode] = useState(
    () => localStorage.getItem("jsc-repl-code") ?? "1 + 1",
  );
  const [jsResult, setJsResult] = useState<string | null>(null);
  const [dumpResult, setDumpResult] = useState<Record<string, unknown> | null>(
    null,
  );
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);

  const {
    data: contexts,
    isLoading,
    refetch,
  } = useRpcQuery<Record<string, string>>(["jsc"], (api) => api.jsc.list());

  const runMutation = useRpcMutation<string, { handle: string; js: string }>(
    (api, { handle, js }) => api.jsc.run(handle, js),
  );

  const dumpMutation = useRpcMutation<
    Record<string, unknown>,
    { handle: string }
  >((api, { handle }) => api.jsc.dump(handle));

  const entries: JSCEntry[] = [];
  if (contexts) {
    for (const [handle, description] of Object.entries(contexts)) {
      entries.push({ handle, description });
    }
  }

  const selectedEntry =
    entries.find((e) => e.handle === selectedHandle) ?? null;

  const selectEntry = async (handle: string) => {
    if (selectedHandle === handle) {
      setSelectedHandle(null);
      setJsResult(null);
      setDumpResult(null);
    } else {
      setSelectedHandle(handle);
      setJsResult(null);
      setDumpResult(null);
      // Load globals immediately
      try {
        const result = await dumpMutation.mutateAsync({ handle });
        setDumpResult(result);
      } catch (e) {
        console.error("Failed to dump:", e);
      }
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

  const handleEditorDidMount = (editor: editor.IStandaloneCodeEditor) => {
    editorRef.current = editor;
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
          <RefreshCw
            className={`w-4 h-4 mr-2 ${isLoading ? "animate-spin" : ""}`}
          />
          {t("reload")}
        </Button>
        <span className="text-sm text-muted-foreground ml-auto">
          {t("jsc_contexts", { count: entries.length })}
        </span>
      </div>
      <div className="flex-1 overflow-hidden">
        {!isLoading && entries.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_jscontext_found")}
          </div>
        ) : (
          <ResizablePanelGroup orientation="horizontal">
            {/* Left Panel - JSContext List */}
            <ResizablePanel defaultSize={35} minSize={20}>
              <div className="h-full overflow-auto">
                {isLoading ? (
                  <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
                    <Spinner className="w-5 h-5" />
                    <span>{t("loading")}...</span>
                  </div>
                ) : (
                  <Table>
                    <TableHeader>
                      <TableRow>
                        <TableHead>{t("handle")}</TableHead>
                        <TableHead>{t("description")}</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {entries.map((entry) => (
                        <TableRow
                          key={entry.handle}
                          className={`cursor-pointer ${
                            selectedHandle === entry.handle ? "bg-accent" : ""
                          }`}
                          onClick={() => selectEntry(entry.handle)}
                        >
                          <TableCell className="font-mono text-xs">
                            {entry.handle}
                          </TableCell>
                          <TableCell
                            className="font-mono text-sm truncate max-w-[200px]"
                            title={entry.description}
                          >
                            {entry.description}
                          </TableCell>
                        </TableRow>
                      ))}
                    </TableBody>
                  </Table>
                )}
              </div>
            </ResizablePanel>

            <ResizableHandle withHandle />

            {/* Right Panel - Detail View */}
            <ResizablePanel defaultSize={65} minSize={30}>
              <div className="h-full overflow-hidden">
                {selectedEntry ? (
                  <Tabs
                    value={activeTab}
                    onValueChange={setActiveTab}
                    className="flex flex-col h-full"
                  >
                    <div className="flex items-center justify-between p-2 border-b">
                      <TabsList>
                        <TabsTrigger value="dump">
                          <Braces className="w-4 h-4 mr-1" />
                          {t("globals")}
                        </TabsTrigger>
                        <TabsTrigger value="repl">
                          <Terminal className="w-4 h-4 mr-1" />
                          {t("repl")}
                        </TabsTrigger>
                      </TabsList>
                    </div>

                    <TabsContent value="dump" className="flex-1 min-h-0">
                      {dumpMutation.isPending ? (
                        <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
                          <Spinner className="w-5 h-5" />
                          <span>{t("loading_globals")}</span>
                        </div>
                      ) : dumpResult ? (
                        <DumpView data={dumpResult} t={t} />
                      ) : (
                        <div className="flex items-center justify-center h-full text-muted-foreground">
                          {t("failed_to_load_globals")}
                        </div>
                      )}
                    </TabsContent>

                    <TabsContent value="repl" className="flex-1 min-h-0">
                      <div className="flex flex-col h-full p-4 gap-3">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">
                            {t("execute_javascript")}
                          </span>
                          <Button
                            size="sm"
                            onClick={() => executeJs(selectedEntry.handle)}
                            disabled={runMutation.isPending}
                          >
                            <Play className="w-4 h-4 mr-2" />
                            {t("run")}
                          </Button>
                        </div>
                        <div className="flex-1 min-h-0 border rounded overflow-hidden">
                          <Editor
                            height="100%"
                            language="javascript"
                            value={jsCode}
                            onChange={(value) => {
                              const code = value || "";
                              setJsCode(code);
                              localStorage.setItem("jsc-repl-code", code);
                            }}
                            beforeMount={handleEditorWillMount}
                            onMount={handleEditorDidMount}
                            theme={theme === "dark" ? "vs-dark" : "light"}
                            options={{
                              minimap: { enabled: false },
                              scrollBeyondLastLine: false,
                              fontSize: 13,
                              lineNumbers: "on",
                              folding: true,
                              automaticLayout: true,
                              tabSize: 2,
                              wordWrap: "on",
                              suggestOnTriggerCharacters: true,
                              quickSuggestions: true,
                            }}
                          />
                        </div>
                        {jsResult !== null && (
                          <div className="shrink-0">
                            <div className="text-sm text-muted-foreground mb-1">
                              {t("result")}:
                            </div>
                            <pre className="font-mono text-xs bg-muted p-3 rounded overflow-x-auto max-h-40 whitespace-pre-wrap">
                              {jsResult}
                            </pre>
                          </div>
                        )}
                      </div>
                    </TabsContent>
                  </Tabs>
                ) : (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    {t("select_jscontext")}
                  </div>
                )}
              </div>
            </ResizablePanel>
          </ResizablePanelGroup>
        )}
      </div>
    </div>
  );
}

import { useState, useRef } from "react";
import { useTranslation } from "react-i18next";
import Editor, { type Monaco } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import {
  RefreshCw,
  Play,
  Globe,
  ExternalLink,
  Check,
  X,
  Navigation,
  AlertTriangle,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ButtonGroup } from "@/components/ui/button-group";
import { Input } from "@/components/ui/input";
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
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";
import { useTheme } from "@/components/providers/ThemeProvider";
import { useDroidQuery, useDroidMutation } from "@/lib/queries";

import type { AndroidWebViewInfo } from "@agent/droid/modules/webview";

function handleEditorWillMount(monaco: Monaco) {
  monaco.languages.typescript.javascriptDefaults.setCompilerOptions({
    target: monaco.languages.typescript.ScriptTarget.ESNext,
    allowNonTsExtensions: true,
    lib: ["esnext", "dom", "dom.iterable"],
  });

  monaco.languages.typescript.javascriptDefaults.setDiagnosticsOptions({
    noSemanticValidation: false,
    noSyntaxValidation: false,
  });
}

function BooleanBadge({
  value,
  label,
  danger,
  t,
}: {
  value: boolean;
  label: string;
  danger?: boolean;
  t: (key: string) => string;
}) {
  const isDanger = danger ?? value;
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <span
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${
              isDanger
                ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
            }`}
          />
        }
      >
        {value ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
        {label}
      </TooltipTrigger>
      <TooltipContent>
        {label}: {value ? t("enabled") : t("disabled")}
      </TooltipContent>
    </Tooltip>
  );
}

export function DroidWebViewTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [selectedHandle, setSelectedHandle] = useState<string | null>(null);
  const [jsCode, setJsCode] = useState(`// Execute JavaScript in the WebView
// DOM APIs are available (document, window, etc.)

document.title`);
  const [jsResult, setJsResult] = useState<string | null>(null);
  const [navigateUrl, setNavigateUrl] = useState("");
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);

  const {
    data: webviews = [],
    isLoading,
    refetch,
  } = useDroidQuery(["webviews"], (api) => api.webview.list());

  const evaluateMutation = useDroidMutation(
    (
      api,
      { handle, js }: { handle: string; js: string },
    ) => api.webview.evaluate(handle, js),
  );

  const navigateMutation = useDroidMutation(
    (
      api,
      { handle, url }: { handle: string; url: string },
    ) => api.webview.navigate(handle, url),
  );

  const selectedEntry =
    webviews.find((e) => e.handle === selectedHandle) ?? null;

  const selectEntry = (handle: string) => {
    if (selectedHandle === handle) {
      setSelectedHandle(null);
      setJsResult(null);
    } else {
      setSelectedHandle(handle);
      setJsResult(null);
    }
  };

  const executeJs = async (entry: AndroidWebViewInfo) => {
    try {
      const result = await evaluateMutation.mutateAsync({
        handle: entry.handle,
        js: jsCode,
      });
      setJsResult(String(result));
    } catch (e) {
      setJsResult(`Error: ${(e as Error).message}`);
    }
  };

  const doNavigate = async (entry: AndroidWebViewInfo) => {
    if (!navigateUrl) return;
    try {
      await navigateMutation.mutateAsync({
        handle: entry.handle,
        url: navigateUrl,
      });
      setNavigateUrl("");
      refetch();
    } catch (e) {
      console.error("Failed to navigate:", e);
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
          <RefreshCw className="w-4 h-4 mr-2" />
          {t("reload")}
        </Button>
        <span className="text-sm text-muted-foreground ml-auto">
          {webviews.length} {t("webviews")}
        </span>
      </div>
      <div className="flex-1 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner className="w-5 h-5" />
            <span>{t("loading")}...</span>
          </div>
        ) : webviews.length === 0 ? (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_webviews")}
          </div>
        ) : (
          <ResizablePanelGroup orientation="horizontal">
            {/* Left Panel - WebView List */}
            <ResizablePanel defaultSize="40%" minSize="25%">
              <div className="h-full overflow-auto">
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-24">{t("handle")}</TableHead>
                      <TableHead>
                        {t("title")} / URL
                      </TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {webviews.map((entry) => (
                      <TableRow
                        key={entry.handle}
                        className={`cursor-pointer ${
                          selectedHandle === entry.handle ? "bg-accent" : ""
                        }`}
                        onClick={() => selectEntry(entry.handle)}
                      >
                        <TableCell>
                          <span className="px-2 py-1 text-xs rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200">
                            WebView
                          </span>
                        </TableCell>
                        <TableCell>
                          <div
                            className="truncate font-medium"
                            title={entry.title}
                          >
                            {entry.title || "-"}
                          </div>
                          <div
                            className="truncate text-xs text-muted-foreground font-mono"
                            title={entry.url}
                          >
                            {entry.url || "-"}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </div>
            </ResizablePanel>

            <ResizableHandle withHandle />

            {/* Right Panel - Detail View */}
            <ResizablePanel defaultSize="60%" minSize="30%">
              <div className="h-full overflow-auto">
                {selectedEntry ? (
                  <div className="flex flex-col h-full p-4 gap-4">
                    {/* Header */}
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-1 text-xs rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200">
                        WebView
                      </span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {selectedEntry.handle}
                      </span>
                    </div>

                    {/* Security Configuration */}
                    <div>
                      <div className="text-sm font-medium mb-2">
                        {t("configuration")}
                      </div>
                      <div className="flex flex-wrap gap-2">
                        <BooleanBadge
                          value={selectedEntry.javaScriptEnabled}
                          label="JavaScript"
                          t={t}
                        />
                        <BooleanBadge
                          value={selectedEntry.allowFileAccess}
                          label={t("file_url_access")}
                          t={t}
                        />
                        <BooleanBadge
                          value={selectedEntry.allowContentAccess}
                          label="Content Access"
                          t={t}
                        />
                        <BooleanBadge
                          value={selectedEntry.allowFileAccessFromFileURLs}
                          label="File Access From File URLs"
                          t={t}
                        />
                        <BooleanBadge
                          value={selectedEntry.allowUniversalAccessFromFileURLs}
                          label={t("universal_file_access")}
                          t={t}
                        />
                        <BooleanBadge
                          value={selectedEntry.domStorageEnabled}
                          label="DOM Storage"
                          danger={false}
                          t={t}
                        />
                        <BooleanBadge
                          value={selectedEntry.databaseEnabled}
                          label="Database"
                          danger={false}
                          t={t}
                        />
                        <Tooltip>
                          <TooltipTrigger
                            render={
                              <span
                                className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${
                                  selectedEntry.mixedContentMode === 0
                                    ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                                    : selectedEntry.mixedContentMode === 1
                                      ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                                      : "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
                                }`}
                              />
                            }
                          >
                            {selectedEntry.mixedContentMode === 0 && (
                              <AlertTriangle className="w-3 h-3" />
                            )}
                            Mixed: {selectedEntry.mixedContentModeName}
                          </TooltipTrigger>
                          <TooltipContent>
                            Mixed content mode: {selectedEntry.mixedContentModeName}
                          </TooltipContent>
                        </Tooltip>
                      </div>
                    </div>

                    {/* JS Interfaces */}
                    {selectedEntry.jsInterfaceNames.length > 0 && (
                      <div>
                        <div className="text-sm font-medium mb-2">
                          JavaScript Interfaces
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {selectedEntry.jsInterfaceNames.map((name) => (
                            <span
                              key={name}
                              className="inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
                            >
                              <AlertTriangle className="w-3 h-3" />
                              {name}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* User Agent */}
                    {selectedEntry.userAgent && (
                      <div>
                        <div className="text-sm font-medium mb-1">
                          User Agent
                        </div>
                        <div className="font-mono text-xs bg-muted p-2 rounded break-all">
                          {selectedEntry.userAgent}
                        </div>
                      </div>
                    )}

                    {/* Current URL */}
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Globe className="w-4 h-4 text-muted-foreground" />
                        <span className="text-sm font-medium">
                          {t("current_url")}
                        </span>
                      </div>
                      <div className="font-mono text-sm bg-muted p-2 rounded flex items-center gap-2">
                        <span className="truncate flex-1">
                          {selectedEntry.url || "about:blank"}
                        </span>
                        {selectedEntry.url && (
                          <a
                            href={selectedEntry.url}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="text-emerald-500 hover:text-emerald-600 shrink-0"
                          >
                            <ExternalLink className="w-4 h-4" />
                          </a>
                        )}
                      </div>
                    </div>

                    {/* Navigate */}
                    <div>
                      <div className="text-sm font-medium mb-2">
                        {t("navigate_to_url")}
                      </div>
                      <ButtonGroup className="w-full">
                        <Input
                          placeholder="https://example.com"
                          value={navigateUrl}
                          onChange={(e) => setNavigateUrl(e.target.value)}
                          onKeyDown={(e) => {
                            if (e.key === "Enter" && navigateUrl) {
                              doNavigate(selectedEntry);
                            }
                          }}
                          className="flex-1"
                        />
                        <Button
                          variant="outline"
                          onClick={() => doNavigate(selectedEntry)}
                          disabled={!navigateUrl || navigateMutation.isPending}
                          title={t("navigate")}
                        >
                          <Navigation className="w-4 h-4" />
                        </Button>
                      </ButtonGroup>
                    </div>

                    {/* Execute JavaScript - fills remaining space */}
                    <div className="flex flex-col flex-1 min-h-0">
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-sm font-medium">
                          {t("execute_javascript")}
                        </span>
                        <Button
                          size="sm"
                          onClick={() => executeJs(selectedEntry)}
                          disabled={evaluateMutation.isPending}
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
                          onChange={(value) => setJsCode(value || "")}
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
                        <div className="mt-3 shrink-0">
                          <div className="text-sm text-muted-foreground mb-1">
                            {t("result")}:
                          </div>
                          <pre className="font-mono text-xs bg-muted p-3 rounded overflow-x-auto max-h-32 whitespace-pre-wrap">
                            {jsResult}
                          </pre>
                        </div>
                      )}
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-center h-full text-muted-foreground">
                    {t("select_webview")}
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

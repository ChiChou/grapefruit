import { useState, useRef } from "react";
import { useTranslation } from "react-i18next";
import Editor, { type Monaco } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import {
  RotateCcw,
  Play,
  Globe,
  ExternalLink,
  Check,
  X,
  Navigation,
} from "lucide-react";
import { Button } from "@/components/ui/button";
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
import { useTheme } from "@/components/theme-provider";
import { useRpcQuery, useRpcMutation } from "@/lib/queries";

import type {
  WKWebViewInfo,
  UIWebViewInfo,
} from "../../../../agent/types/fruity/modules/webview";

type WebViewKind = "UI" | "WK";
type WebViewEntry = WKWebViewInfo | UIWebViewInfo;

// Configure Monaco to include DOM types for JavaScript
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

function isWKWebView(entry: WebViewEntry): entry is WKWebViewInfo {
  return entry.kind === "WK";
}

function BooleanBadge({ value, label }: { value: boolean | undefined; label: string }) {
  if (value === undefined) return null;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span
          className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${
            value
              ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
              : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
          }`}
        >
          {value ? <Check className="w-3 h-3" /> : <X className="w-3 h-3" />}
          {label}
        </span>
      </TooltipTrigger>
      <TooltipContent>
        {label}: {value ? "Enabled" : "Disabled"}
      </TooltipContent>
    </Tooltip>
  );
}

export function WebViewTab() {
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
    data: wkWebviews = [],
    isLoading: isLoadingWK,
    refetch: refetchWK,
  } = useRpcQuery<WKWebViewInfo[]>(["webviews", "wk"], (api) =>
    api.webview.listWK()
  );

  const {
    data: uiWebviews = [],
    isLoading: isLoadingUI,
    refetch: refetchUI,
  } = useRpcQuery<UIWebViewInfo[]>(["webviews", "ui"], (api) =>
    api.webview.listUI()
  );

  const isLoading = isLoadingWK || isLoadingUI;

  const evaluateMutation = useRpcMutation<
    unknown,
    { kind: WebViewKind; handle: string; js: string }
  >((api, { kind, handle, js }) => api.webview.evaluate(kind, handle, js));

  const navigateMutation = useRpcMutation<
    void,
    { kind: WebViewKind; handle: string; url: string }
  >((api, { kind, handle, url }) => api.webview.navigate(kind, handle, url));

  const entries: WebViewEntry[] = [...wkWebviews, ...uiWebviews];
  const selectedEntry = entries.find((e) => e.handle === selectedHandle) ?? null;

  const refetch = () => {
    refetchWK();
    refetchUI();
  };

  const selectEntry = (handle: string) => {
    if (selectedHandle === handle) {
      setSelectedHandle(null);
      setJsResult(null);
    } else {
      setSelectedHandle(handle);
      setJsResult(null);
    }
  };

  const executeJs = async (entry: WebViewEntry) => {
    try {
      const result = await evaluateMutation.mutateAsync({
        kind: entry.kind,
        handle: entry.handle,
        js: jsCode,
      });
      setJsResult(String(result));
    } catch (e) {
      setJsResult(`Error: ${(e as Error).message}`);
    }
  };

  const doNavigate = async (entry: WebViewEntry) => {
    if (!navigateUrl) return;
    try {
      await navigateMutation.mutateAsync({
        kind: entry.kind,
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
          <RotateCcw className="w-4 h-4 mr-2" />
          {t("reload")}
        </Button>
        <span className="text-sm text-muted-foreground ml-auto">
          {entries.length} {t("webviews")}
        </span>
      </div>
      <div className="flex-1 overflow-hidden">
        <ResizablePanelGroup direction="horizontal">
          {/* Left Panel - WebView List */}
          <ResizablePanel defaultSize={40} minSize={25}>
            <div className="h-full overflow-auto">
              {isLoading ? (
                <div className="flex items-center justify-center h-full gap-2 text-gray-500">
                  <Spinner className="w-5 h-5" />
                  <span>{t("loading")}...</span>
                </div>
              ) : entries.length === 0 ? (
                <div className="flex items-center justify-center h-full text-gray-500">
                  {t("no_webviews")}
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow>
                      <TableHead className="w-24">{t("type")}</TableHead>
                      <TableHead>{t("title")} / URL</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {entries.map((entry) => (
                      <TableRow
                        key={entry.handle}
                        className={`cursor-pointer ${
                          selectedHandle === entry.handle
                            ? "bg-accent"
                            : ""
                        }`}
                        onClick={() => selectEntry(entry.handle)}
                      >
                        <TableCell>
                          <span
                            className={`px-2 py-1 text-xs rounded ${
                              entry.kind === "WK"
                                ? "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                                : "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
                            }`}
                          >
                            {entry.kind}WebView
                          </span>
                        </TableCell>
                        <TableCell>
                          <div className="truncate font-medium" title={entry.title}>
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
              )}
            </div>
          </ResizablePanel>

          <ResizableHandle withHandle />

          {/* Right Panel - Detail View */}
          <ResizablePanel defaultSize={60} minSize={30}>
            <div className="h-full overflow-auto">
              {selectedEntry ? (
                <div className="flex flex-col h-full p-4 gap-4">
                  {/* Header */}
                  <div className="flex items-center gap-2">
                    <span
                      className={`px-2 py-1 text-xs rounded ${
                        selectedEntry.kind === "WK"
                          ? "bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200"
                          : "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
                      }`}
                    >
                      {selectedEntry.kind}WebView
                    </span>
                    <span className="font-mono text-xs text-muted-foreground">
                      {selectedEntry.handle}
                    </span>
                  </div>

                  {/* WKWebView-specific properties */}
                  {isWKWebView(selectedEntry) && (
                    <div>
                      <div className="text-sm font-medium mb-2">{t("configuration")}</div>
                      <div className="flex flex-wrap gap-2">
                        <BooleanBadge value={selectedEntry.js} label="JavaScript" />
                        <BooleanBadge
                          value={selectedEntry.contentJs}
                          label="Content JS"
                        />
                        <BooleanBadge
                          value={selectedEntry.jsAutoOpenWindow}
                          label="Auto-Open Windows"
                        />
                        <BooleanBadge
                          value={selectedEntry.fileURLAccess}
                          label="File URL Access"
                        />
                        <BooleanBadge
                          value={selectedEntry.universalFileAccess}
                          label="Universal File Access"
                        />
                        <BooleanBadge value={selectedEntry.secure} label="Secure" />
                      </div>
                    </div>
                  )}

                  {/* Current URL */}
                  <div>
                    <div className="flex items-center gap-2 mb-2">
                      <Globe className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm font-medium">{t("current_url")}</span>
                    </div>
                    <div className="font-mono text-sm bg-gray-100 dark:bg-gray-800 p-2 rounded flex items-center gap-2">
                      <span className="truncate flex-1">
                        {selectedEntry.url || "about:blank"}
                      </span>
                      {selectedEntry.url && (
                        <a
                          href={selectedEntry.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-blue-500 hover:text-blue-600 shrink-0"
                        >
                          <ExternalLink className="w-4 h-4" />
                        </a>
                      )}
                    </div>
                  </div>

                  {/* Navigate */}
                  <div>
                    <div className="text-sm font-medium mb-2">{t("navigate_to_url")}</div>
                    <div className="flex gap-2">
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
                        size="sm"
                        onClick={() => doNavigate(selectedEntry)}
                        disabled={!navigateUrl || navigateMutation.isPending}
                      >
                        <Navigation className="w-4 h-4 mr-2" />
                        {t("navigate")}
                      </Button>
                    </div>
                  </div>

                  {/* Execute JavaScript - fills remaining space */}
                  <div className="flex flex-col flex-1 min-h-0">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium">{t("execute_javascript")}</span>
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
                        <pre className="font-mono text-xs bg-gray-100 dark:bg-gray-800 p-3 rounded overflow-x-auto max-h-32 whitespace-pre-wrap">
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
      </div>
    </div>
  );
}

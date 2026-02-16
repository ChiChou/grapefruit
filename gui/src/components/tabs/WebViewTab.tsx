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
import { useTheme } from "@/components/theme-provider";
import { useRpcQuery, useRpcMutation } from "@/lib/queries";

import type {
  WKWebViewInfo,
  UIWebViewInfo,
} from "@agent/fruity/modules/webview";

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

function BooleanBadge({
  value,
  label,
  t,
}: {
  value: boolean | undefined;
  label: string;
  t: (key: string) => string;
}) {
  if (value === undefined) return null;
  return (
    <Tooltip>
      <TooltipTrigger
        render={
          <span
            className={`inline-flex items-center gap-1 px-1.5 py-0.5 text-xs rounded ${
              value
                ? "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                : "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
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
  } = useRpcQuery(["webviews", "wk"], (api) => api.webview.listWK());

  const {
    data: uiWebviews = [],
    isLoading: isLoadingUI,
    refetch: refetchUI,
  } = useRpcQuery(["webviews", "ui"], (api) => api.webview.listUI());

  const isLoading = isLoadingWK || isLoadingUI;

  const evaluateMutation = useRpcMutation(
    (
      api,
      { kind, handle, js }: { kind: WebViewKind; handle: string; js: string },
    ) => api.webview.evaluate(kind, handle, js),
  );

  const navigateMutation = useRpcMutation(
    (
      api,
      { kind, handle, url }: { kind: WebViewKind; handle: string; url: string },
    ) => api.webview.navigate(kind, handle, url),
  );

  const entries: WebViewEntry[] = [...wkWebviews, ...uiWebviews];
  const selectedEntry =
    entries.find((e) => e.handle === selectedHandle) ?? null;

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
          <RefreshCw className="w-4 h-4 mr-2" />
          {t("reload")}
        </Button>
        <span className="text-sm text-muted-foreground ml-auto">
          {entries.length} {t("webviews")}
        </span>
      </div>
      <div className="flex-1 overflow-hidden">
        {isLoading ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner className="w-5 h-5" />
            <span>{t("loading")}...</span>
          </div>
        ) : entries.length === 0 ? (
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
                      <TableHead className="w-24">{t("type")}</TableHead>
                      <TableHead>
                        {t("title")} / {t("url")}
                      </TableHead>
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
                        <TableCell>
                          <span
                            className={`px-2 py-1 text-xs rounded ${
                              entry.kind === "WK"
                                ? "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"
                                : "bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200"
                            }`}
                          >
                            {entry.kind}WebView
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
                      <span
                        className={`px-2 py-1 text-xs rounded ${
                          selectedEntry.kind === "WK"
                            ? "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"
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
                        <div className="text-sm font-medium mb-2">
                          {t("configuration")}
                        </div>
                        <div className="flex flex-wrap gap-2">
                          <BooleanBadge
                            value={selectedEntry.js}
                            label={t("javascript")}
                            t={t}
                          />
                          <BooleanBadge
                            value={selectedEntry.contentJs}
                            label={t("content_js")}
                            t={t}
                          />
                          <BooleanBadge
                            value={selectedEntry.jsAutoOpenWindow}
                            label={t("auto_open_windows")}
                            t={t}
                          />
                          <BooleanBadge
                            value={selectedEntry.fileURLAccess}
                            label={t("file_url_access")}
                            t={t}
                          />
                          <BooleanBadge
                            value={selectedEntry.universalFileAccess}
                            label={t("universal_file_access")}
                            t={t}
                          />
                          <BooleanBadge
                            value={selectedEntry.secure}
                            label={t("secure")}
                            t={t}
                          />
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
                            className="text-amber-500 hover:text-amber-600 shrink-0"
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

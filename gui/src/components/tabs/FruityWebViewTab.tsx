import { useState, useRef } from "react";
import { useTranslation } from "react-i18next";
import Editor, { type Monaco } from "@monaco-editor/react";
import type { editor } from "monaco-editor";
import {
  RefreshCw,
  Play,
  Globe,
  Navigation,
  ShieldAlert,
  Shield,
  ShieldOff,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { ButtonGroup } from "@/components/ui/button-group";
import { Input } from "@/components/ui/input";
import { Spinner } from "@/components/ui/spinner";
import { Switch } from "@/components/ui/switch";
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
import { useTheme } from "@/components/providers/ThemeProvider";
import { useFruityQuery, useFruityMutation } from "@/lib/queries";

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

// Settings that are risky when enabled
const RISKY_WHEN_TRUE = new Set([
  "js",
  "contentJs",
  "jsAutoOpenWindow",
  "fileURLAccess",
  "universalFileAccess",
]);

// Settings that are risky when disabled
const RISKY_WHEN_FALSE = new Set(["secure"]);

const SETTING_LABELS: Record<string, string> = {
  js: "javaScriptEnabled",
  contentJs: "allowsContentJavaScript",
  jsAutoOpenWindow: "javaScriptCanOpenWindowsAutomatically",
  fileURLAccess: "allowFileAccessFromFileURLs",
  universalFileAccess: "allowUniversalAccessFromFileURLs",
  secure: "contentBlockersEnabled",
};

function settingColor(key: string, value: boolean): string {
  if (RISKY_WHEN_TRUE.has(key)) {
    return value
      ? "text-red-600 dark:text-red-400"
      : "text-green-600 dark:text-green-400";
  }
  if (RISKY_WHEN_FALSE.has(key)) {
    return value
      ? "text-green-600 dark:text-green-400"
      : "text-red-600 dark:text-red-400";
  }
  return "text-muted-foreground";
}

function riskCount(entry: WebViewEntry): number {
  if (!isWKWebView(entry)) return 0;
  let count = 0;
  if (entry.js) count++;
  if (entry.contentJs) count++;
  if (entry.jsAutoOpenWindow) count++;
  if (entry.fileURLAccess) count++;
  if (entry.universalFileAccess) count++;
  if (entry.secure === false) count++;
  return count;
}

export function FruityWebViewTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [selectedHandle, setSelectedHandle] = useState<string | null>(null);
  const [jsCode, setJsCode] = useState(`// Execute JavaScript in the WebView
// DOM APIs are available (document, window, etc.)

document.title`);
  const [jsResult, setJsResult] = useState<string | null>(null);
  const [urlBar, setUrlBar] = useState("");
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);

  const {
    data: wkWebviews = [],
    isLoading: isLoadingWK,
    refetch: refetchWK,
  } = useFruityQuery(["webviews", "wk"], (api) => api.webview.listWK());

  const {
    data: uiWebviews = [],
    isLoading: isLoadingUI,
    refetch: refetchUI,
  } = useFruityQuery(["webviews", "ui"], (api) => api.webview.listUI());

  const isLoading = isLoadingWK || isLoadingUI;

  const evaluateMutation = useFruityMutation(
    (
      api,
      { kind, handle, js }: { kind: WebViewKind; handle: string; js: string },
    ) => api.webview.evaluate(kind, handle, js),
  );

  const navigateMutation = useFruityMutation(
    (
      api,
      { kind, handle, url }: { kind: WebViewKind; handle: string; url: string },
    ) => api.webview.navigate(kind, handle, url),
  );

  const inspectableMutation = useFruityMutation(
    (
      api,
      { handle, enabled }: { handle: string; enabled: boolean },
    ) => api.webview.setInspectable(handle, enabled),
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
      const entry = entries.find((e) => e.handle === handle);
      setUrlBar(entry?.url || "");
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
    if (!urlBar || urlBar === entry.url) return;
    try {
      await navigateMutation.mutateAsync({
        kind: entry.kind,
        handle: entry.handle,
        url: urlBar,
      });
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
                      <TableHead className="w-20">Risk</TableHead>
                      <TableHead>{t("title")} / URL</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {entries.map((entry) => {
                      const risks = riskCount(entry);
                      return (
                        <TableRow
                          key={entry.handle}
                          className={`cursor-pointer ${
                            selectedHandle === entry.handle ? "bg-accent" : ""
                          }`}
                          onClick={() => selectEntry(entry.handle)}
                        >
                          <TableCell>
                            <span
                              className={`inline-flex items-center gap-1 px-2 py-1 text-xs rounded ${
                                risks >= 3
                                  ? "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
                                  : risks >= 1
                                    ? "bg-amber-100 text-amber-800 dark:bg-amber-900 dark:text-amber-200"
                                    : "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
                              }`}
                            >
                              {risks >= 3 ? (
                                <ShieldAlert className="w-3 h-3" />
                              ) : risks >= 1 ? (
                                <ShieldOff className="w-3 h-3" />
                              ) : (
                                <Shield className="w-3 h-3" />
                              )}
                              {risks}
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
                      );
                    })}
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
                      {isWKWebView(selectedEntry) &&
                        selectedEntry.inspectable !== undefined && (
                          <label className="flex items-center gap-1.5 ml-auto text-xs text-muted-foreground cursor-pointer">
                            Inspectable
                            <Switch
                              size="sm"
                              checked={selectedEntry.inspectable}
                              onCheckedChange={(checked) => {
                                inspectableMutation.mutate(
                                  {
                                    handle: selectedEntry.handle,
                                    enabled: checked,
                                  },
                                  { onSuccess: () => refetch() },
                                );
                              }}
                              disabled={inspectableMutation.isPending}
                            />
                          </label>
                        )}
                    </div>

                    {/* WKWebView configuration table */}
                    {isWKWebView(selectedEntry) && (
                      <div>
                        <div className="text-sm font-medium mb-2">
                          WKPreferences
                        </div>
                        <Table>
                          <TableBody>
                            {(
                              [
                                ["js", selectedEntry.js],
                                ["contentJs", selectedEntry.contentJs],
                                [
                                  "jsAutoOpenWindow",
                                  selectedEntry.jsAutoOpenWindow,
                                ],
                                [
                                  "fileURLAccess",
                                  selectedEntry.fileURLAccess,
                                ],
                                [
                                  "universalFileAccess",
                                  selectedEntry.universalFileAccess,
                                ],
                                ["secure", selectedEntry.secure],
                              ] as [string, boolean | undefined][]
                            )
                              .filter(([, v]) => v !== undefined)
                              .map(([key, value]) => (
                                <TableRow key={key}>
                                  <TableCell className="py-1 font-mono text-xs">
                                    {SETTING_LABELS[key] ?? key}
                                  </TableCell>
                                  <TableCell className="py-1 text-xs text-right">
                                    <span
                                      className={settingColor(
                                        key,
                                        value as boolean,
                                      )}
                                    >
                                      {String(value)}
                                    </span>
                                  </TableCell>
                                </TableRow>
                              ))}
                          </TableBody>
                        </Table>
                      </div>
                    )}

                    {/* URL Bar */}
                    <ButtonGroup className="w-full">
                      <span className="inline-flex items-center px-2 border border-r-0 rounded-l-md bg-muted text-muted-foreground">
                        <Globe className="w-4 h-4" />
                      </span>
                      <Input
                        placeholder="about:blank"
                        value={urlBar}
                        onChange={(e) => setUrlBar(e.target.value)}
                        onKeyDown={(e) => {
                          if (e.key === "Enter") {
                            doNavigate(selectedEntry);
                          }
                        }}
                        className="flex-1 font-mono text-sm rounded-l-none"
                      />
                      <Button
                        variant="outline"
                        onClick={() => doNavigate(selectedEntry)}
                        disabled={
                          !urlBar ||
                          urlBar === selectedEntry.url ||
                          navigateMutation.isPending
                        }
                        title={t("navigate")}
                      >
                        <Navigation className="w-4 h-4" />
                      </Button>
                    </ButtonGroup>

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

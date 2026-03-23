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
import { useDroidQuery, useDroidMutation } from "@/lib/queries";

import type { AndroidWebViewInfo } from "@agent/droid/modules/webview";

const MIXED_CONTENT_LABELS: Record<number, string> = {
  0: "ALWAYS_ALLOW",
  1: "NEVER_ALLOW",
  2: "COMPATIBILITY_MODE",
};

const RISKY_WHEN_TRUE = new Set([
  "jsEnabled",
  "allowFileAccess",
  "allowContentAccess",
  "allowFileAccessFromFileURLs",
  "allowUniversalAccessFromFileURLs",
  "databaseEnabled",
  "domStorageEnabled",
]);

const RISKY_WHEN_FALSE = new Set(["safeBrowsingEnabled"]);

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

export function DroidWebViewTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [selectedHandle, setSelectedHandle] = useState<string | null>(null);
  const [jsCode, setJsCode] = useState(`// Execute JavaScript in the WebView
// DOM APIs are available (document, window, etc.)

document.title`);
  const [jsResult, setJsResult] = useState<string | null>(null);
  const [urlBar, setUrlBar] = useState("");
  const [debugEnabled, setDebugEnabled] = useState(false);
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);

  const {
    data: webviews = [],
    isLoading,
    refetch,
  } = useDroidQuery(["webviews"], (api) => api.webview.list(), {
    refetchInterval: 3000,
  });

  const evaluateMutation = useDroidMutation(
    (api, { handle, js }: { handle: string; js: string }) =>
      api.webview.evaluate(handle, js),
  );

  const navigateMutation = useDroidMutation(
    (api, { handle, url }: { handle: string; url: string }) =>
      api.webview.navigate(handle, url),
  );

  const debugMutation = useDroidMutation(
    (api, { handle, enabled }: { handle: string; enabled: boolean }) =>
      api.webview.setDebugging(handle, enabled),
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
      const entry = webviews.find((e) => e.handle === handle);
      setUrlBar(entry?.url || "");
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
    if (!urlBar || urlBar === entry.url) return;
    try {
      await navigateMutation.mutateAsync({
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

  const riskCount = (entry: AndroidWebViewInfo) => {
    const s = entry.settings;
    let count = 0;
    if (s.jsEnabled) count++;
    if (s.allowFileAccess) count++;
    if (s.allowContentAccess) count++;
    if (s.allowFileAccessFromFileURLs) count++;
    if (s.allowUniversalAccessFromFileURLs) count++;
    if (!s.safeBrowsingEnabled) count++;
    if (s.mixedContentMode !== 1) count++;
    return count;
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
                    {webviews.map((entry) => {
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

            <ResizablePanel defaultSize="60%" minSize="30%">
              <div className="h-full overflow-auto">
                {selectedEntry ? (
                  <div className="flex flex-col h-full p-4 gap-4">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-1 text-xs rounded bg-emerald-100 text-emerald-800 dark:bg-emerald-900 dark:text-emerald-200">
                        WebView
                      </span>
                      <span className="font-mono text-xs text-muted-foreground">
                        {selectedEntry.handle}
                      </span>
                      <label className="flex items-center gap-1.5 ml-auto text-xs text-muted-foreground cursor-pointer">
                        Remote Debugging
                        <Switch
                          size="sm"
                          checked={debugEnabled}
                          onCheckedChange={(checked) => {
                            setDebugEnabled(checked);
                            debugMutation.mutate({
                              handle: selectedEntry.handle,
                              enabled: checked,
                            });
                          }}
                          disabled={debugMutation.isPending}
                        />
                      </label>
                    </div>

                    <div>
                      <div className="text-sm font-medium mb-2">
                        WebSettings
                      </div>
                      <Table>
                        <TableBody>
                          {(
                            Object.entries(selectedEntry.settings) as [
                              string,
                              boolean | number,
                            ][]
                          ).map(([key, value]) => (
                            <TableRow key={key}>
                              <TableCell className="py-1 font-mono text-xs">
                                {key}
                              </TableCell>
                              <TableCell className="py-1 text-xs text-right">
                                {typeof value === "boolean" ? (
                                  <span className={settingColor(key, value)}>
                                    {String(value)}
                                  </span>
                                ) : key === "mixedContentMode" ? (
                                  <span
                                    className={`font-mono ${
                                      value !== 1
                                        ? "text-red-600 dark:text-red-400"
                                        : "text-green-600 dark:text-green-400"
                                    }`}
                                  >
                                    {MIXED_CONTENT_LABELS[value] ??
                                      String(value)}
                                  </span>
                                ) : (
                                  <span className="font-mono">
                                    {String(value)}
                                  </span>
                                )}
                              </TableCell>
                            </TableRow>
                          ))}
                        </TableBody>
                      </Table>
                    </div>

                    {selectedEntry.interfaces.length > 0 && (
                      <div>
                        <div className="text-sm font-medium mb-2">
                          JavaScript Interfaces
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {selectedEntry.interfaces.map((name) => (
                            <span
                              key={name}
                              className="inline-flex items-center px-2 py-0.5 text-xs rounded bg-violet-100 text-violet-800 dark:bg-violet-900 dark:text-violet-200 font-mono"
                            >
                              {name}
                            </span>
                          ))}
                        </div>
                      </div>
                    )}

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

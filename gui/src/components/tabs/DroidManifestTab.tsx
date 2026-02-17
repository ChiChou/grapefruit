import { useState, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Copy, Check, Download, Printer } from "lucide-react";
import Editor from "@monaco-editor/react";

import { useTheme } from "@/components/providers/ThemeProvider";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { XMLTree } from "@/components/shared/XMLTree";
import { ManifestInsights } from "@/components/tabs/ManifestInsights";
import { useDroidRpcQuery } from "@/lib/queries";

export function DroidManifestTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [viewMode, setViewMode] = useState<"xml" | "insight" | "tree">("xml");
  const [copied, setCopied] = useState(false);
  const [permsOpen, setPermsOpen] = useState(false);
  const insightsRef = useRef<HTMLDivElement>(null);

  const {
    data: xml,
    isLoading,
    error,
  } = useDroidRpcQuery(["manifest"], (api) => api.manifest.xml());

  const handleCopy = async () => {
    if (!xml) return;
    await navigator.clipboard.writeText(xml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleDownload = () => {
    if (!xml) return;
    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "AndroidManifest.xml";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handlePrint = () => {
    // Ensure permissions are expanded so they appear in the captured DOM
    setPermsOpen(true);
    // Wait one render tick for React to commit the expanded state
    setTimeout(() => {
      const el = insightsRef.current;
      if (!el) return;

      const win = window.open("", "_blank");
      if (!win) return;

      // win.addEventListener("load", () => {
      //   win.focus();
      //   win.print();
      //   win.close();
      // });

      win.focus();

      const linkTags = Array.from(document.querySelectorAll('link[rel="stylesheet"]'))
        .map((l) => l.outerHTML)
        .join("\n");
      const styleTags = Array.from(document.querySelectorAll("style"))
        .map((s) => s.outerHTML)
        .join("\n");

      win.document.write(`<!DOCTYPE html>
<html><head>
  <meta charset="utf-8">
  <title>AndroidManifest.xml Insights</title>
  ${linkTags}
  ${styleTags}
  <style>
    /* reset layout constraints for print */
    .h-full { height: auto !important; }
    .overflow-auto, .overflow-hidden { overflow: visible !important; }
    body { padding: 1rem; background: white; color: black; }
  </style>
</head>
<body>${el.innerHTML}</body>
</html>`);
      win.document.close();
    }, 0);
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center p-4 border-b">
        <Tabs
          value={viewMode}
          onValueChange={(v) => setViewMode(v as "xml" | "insight" | "tree")}
        >
          <TabsList variant="line" className="w-auto h-8">
            <TabsTrigger value="xml" className="px-3">
              XML
            </TabsTrigger>
            <TabsTrigger value="insight" className="px-3">
              {t("insights")}
            </TabsTrigger>
            <TabsTrigger value="tree" className="px-3">
              {t("tree")}
            </TabsTrigger>
          </TabsList>
        </Tabs>
      </div>
      <div className="flex-1 overflow-hidden">
        {error ? (
          <div className="p-4">
            <Alert variant="destructive">
              <AlertTitle>{t("error")}</AlertTitle>
              <AlertDescription>{(error as Error)?.message}</AlertDescription>
            </Alert>
          </div>
        ) : isLoading ? (
          <div className="p-4 space-y-4">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        ) : xml ? (
          <Tabs
            value={viewMode}
            onValueChange={(v) => setViewMode(v as "xml" | "insight" | "tree")}
            className="h-full flex flex-col"
          >
            <TabsContent value="xml" className="flex-1 m-0 flex flex-col overflow-hidden">
              <div className="flex items-center gap-2 px-4 py-2 border-b">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleCopy}
                  disabled={!xml}
                >
                  {copied ? (
                    <Check className="h-4 w-4 mr-2 text-green-500" />
                  ) : (
                    <Copy className="h-4 w-4 mr-2" />
                  )}
                  {t("copy")}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={handleDownload}
                  disabled={!xml}
                >
                  <Download className="h-4 w-4 mr-2" />
                  {t("download")}
                </Button>
              </div>
              <div className="flex-1">
                <Editor
                  height="100%"
                  language="xml"
                  value={xml}
                  theme={theme === "dark" ? "vs-dark" : "light"}
                  options={{
                    readOnly: true,
                    minimap: { enabled: false },
                    scrollBeyondLastLine: false,
                    wordWrap: "on",
                    fontSize: 13,
                    lineNumbers: "on",
                    folding: true,
                    automaticLayout: true,
                  }}
                />
              </div>
            </TabsContent>
            <TabsContent value="insight" className="flex-1 overflow-hidden m-0 flex flex-col">
              <div className="flex items-center gap-2 px-4 py-2 border-b">
                <Button variant="outline" size="sm" onClick={handlePrint}>
                  <Printer className="h-4 w-4 mr-2" />
                  {t("print")}
                </Button>
              </div>
              <div ref={insightsRef} className="flex-1 overflow-hidden">
                <ManifestInsights xml={xml} permsOpen={permsOpen} setPermsOpen={setPermsOpen} />
              </div>
            </TabsContent>
            <TabsContent value="tree" className="flex-1 overflow-auto m-0">
              <XMLTree xml={xml} />
            </TabsContent>
          </Tabs>
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_content")}
          </div>
        )}
      </div>
    </div>
  );
}

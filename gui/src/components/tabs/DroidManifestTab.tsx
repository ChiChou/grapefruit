import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Copy, Check, Download } from "lucide-react";
import Editor from "@monaco-editor/react";

import { useTheme } from "@/components/providers/ThemeProvider";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { XMLTree } from "@/components/shared/XMLTree";
import { useDroidRpcQuery } from "@/lib/queries";

export function DroidManifestTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [viewMode, setViewMode] = useState<"xml" | "tree">("xml");
  const [copied, setCopied] = useState(false);

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

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between p-4 border-b">
        <Tabs
          value={viewMode}
          onValueChange={(v) => setViewMode(v as "xml" | "tree")}
        >
          <TabsList variant="line" className="w-auto h-8">
            <TabsTrigger value="xml" className="px-3">
              XML
            </TabsTrigger>
            <TabsTrigger value="tree" className="px-3">
              {t("tree")}
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <div className="flex items-center gap-2">
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
            onValueChange={(v) => setViewMode(v as "xml" | "tree")}
            className="h-full flex flex-col"
          >
            <TabsContent value="xml" className="flex-1 m-0">
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

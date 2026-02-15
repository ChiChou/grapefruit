import { useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Download, Copy, Check, ChevronDown, ChevronUp } from "lucide-react";
import Editor, { loader } from "@monaco-editor/react";
import { useTheme } from "@/components/theme-provider";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import PlistTreeView, { type PlistValue } from "@/components/PlistTreeView";

export type { PlistValue };

loader.init().then((monaco) => {
  monaco.languages.register({ id: "xml" });
});

export interface PlistViewParams {
  xml: string;
  value: PlistValue;
  filename?: string;
}

export function PlistView({
  xml,
  value,
  filename = "Info.plist",
}: PlistViewParams) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const [copied, setCopied] = useState<boolean>(false);
  const [expandAll, setExpandAll] = useState(false);
  const [viewMode, setViewMode] = useState<"tree" | "text">("text");

  const handleDownload = () => {
    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopy = async () => {
    await navigator.clipboard.writeText(xml);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleExpandAll = () => setExpandAll(true);
  const handleCollapseAll = () => setExpandAll(false);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between p-4 border-b">
        <Tabs
          value={viewMode}
          onValueChange={(v) => setViewMode(v as "tree" | "text")}
        >
          <TabsList variant="line" className="w-auto h-8">
            <TabsTrigger value="tree" className="px-3">
              {t("tree")}
            </TabsTrigger>
            <TabsTrigger value="text" className="px-3">
              {t("text")}
            </TabsTrigger>
          </TabsList>
        </Tabs>
        <div className="flex items-center gap-2">
          {viewMode === "tree" && (
            <>
              <Button variant="outline" size="sm" onClick={handleExpandAll}>
                <ChevronDown className="h-4 w-4 mr-2" />
                {t("expand_all")}
              </Button>
              <Button variant="outline" size="sm" onClick={handleCollapseAll}>
                <ChevronUp className="h-4 w-4 mr-2" />
                {t("collapse_all")}
              </Button>
            </>
          )}
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
        <Tabs
          value={viewMode}
          onValueChange={(v) => setViewMode(v as "tree" | "text")}
          className="h-full flex flex-col"
        >
          <TabsContent value="tree" className="flex-1 overflow-auto p-4 m-0">
            {value ? (
              <PlistTreeView data={value} expanded={expandAll} />
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                {t("no_content")}
              </div>
            )}
          </TabsContent>
          <TabsContent value="text" className="flex-1 m-0">
            {xml ? (
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
            ) : (
              <div className="flex items-center justify-center h-full text-muted-foreground">
                {t("no_content")}
              </div>
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

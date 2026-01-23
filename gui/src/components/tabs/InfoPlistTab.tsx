import { Status, useSession } from "@/context/SessionContext";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Download, Copy, Check, ChevronDown, ChevronUp } from "lucide-react";
import Editor, { loader } from "@monaco-editor/react";
import { useTheme } from "@/components/theme-provider";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import PlistTreeView, { type PlistValue } from "@/components/PlistTreeView";

loader.init().then((monaco) => {
  monaco.languages.register({ id: "xml" });
});

export function InfoPlistTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { api, status } = useSession();
  const [loading, setLoading] = useState<boolean>(false);
  const [xml, setXml] = useState<string>("");
  const [copied, setCopied] = useState<boolean>(false);
  const [expandAll, setExpandAll] = useState(false);
  const [plistData, setPlistData] = useState<PlistValue | null>(null);
  const [viewMode, setViewMode] = useState<"tree" | "text">("text");

  useEffect(() => {
    if (!api || status !== Status.Ready) return;

    setLoading(true);
    api.info
      .plist()
      .then(({ xml, value }) => {
        setXml(xml);
        setPlistData(value);
      })
      .finally(() => setLoading(false));
  }, [status, api]);

  const handleDownload = () => {
    const blob = new Blob([xml], { type: "application/xml" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "Info.plist";
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
          <TabsList className="w-auto h-8">
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
              <Button
                variant="outline"
                size="sm"
                onClick={handleExpandAll}
              >
                <ChevronDown className="h-4 w-4 mr-2" />
                {t("expand_all")}
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleCollapseAll}
              >
                <ChevronUp className="h-4 w-4 mr-2" />
                {t("collapse_all")}
              </Button>
            </>
          )}
          <Button
            variant="outline"
            size="sm"
            onClick={handleCopy}
            disabled={loading || !xml}
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
            disabled={loading || !xml}
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
            {loading ? (
              <div className="flex items-center justify-center h-full text-gray-500">
                {t("loading")}...
              </div>
            ) : plistData ? (
              <PlistTreeView data={plistData} expanded={expandAll} />
            ) : (
              <div className="flex items-center justify-center h-full text-gray-500">
                {t("no_content")}
              </div>
            )}
          </TabsContent>
          <TabsContent value="text" className="flex-1 m-0">
            {loading ? (
              <div className="flex items-center justify-center h-full text-gray-500">
                {t("loading")}...
              </div>
            ) : (
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
            )}
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Download } from "lucide-react";
import Editor, { loader } from "@monaco-editor/react";
import { useTheme } from "@/components/theme-provider";

// Configure Monaco to only load typescript, javascript, and xml languages
loader.init().then((monaco) => {
  // Register XML language if not already registered
  monaco.languages.register({ id: "xml" });
});

export function InfoPlistTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { api, status } = useSession();
  const [loading, setLoading] = useState<boolean>(false);
  const [xml, setXml] = useState<string>("");

  useEffect(() => {
    if (!api || status !== ConnectionStatus.Ready) return;

    setLoading(true);
    api.info
      .plistReadable()
      .then((readable) => setXml(readable))
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

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between p-4">
        <h2 className="text-xl font-semibold">Info.plist</h2>
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
      <div className="flex-1 border-t border-gray-300 dark:border-gray-700">
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
      </div>
    </div>
  );
}

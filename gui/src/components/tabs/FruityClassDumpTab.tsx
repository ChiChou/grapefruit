import { useCallback, useMemo } from "react";
import { Copy, Download, Loader2 } from "lucide-react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import type { IDockviewPanelProps } from "dockview";
import Editor, { loader } from "@monaco-editor/react";

import { useTheme } from "@/components/providers/ThemeProvider";
import { Button } from "@/components/ui/button";
import { useFruityQuery } from "@/lib/queries";
import { header, type ClassDumpInfo } from "../../lib/classdump-header.ts";

import type { ClassDetail } from "@agent/fruity/modules/classdump";

loader.init().then((monaco) => {
  monaco.languages.register({ id: "objective-c" });
});

export interface ClassDumpParams {
  className: string;
}

export function FruityClassDumpTab({
  params,
}: IDockviewPanelProps<ClassDumpParams>) {
  const { t } = useTranslation();
  const { theme } = useTheme();

  const { data: classInfo, isLoading } = useFruityQuery<ClassDetail>(
    ["classDetail", params.className],
    (api) => api.classdump.inspect(params.className),
  );

  const content = useMemo(
    () => (classInfo ? header(classInfo as ClassDumpInfo) : ""),
    [classInfo],
  );

  const handleCopy = useCallback(() => {
    navigator.clipboard.writeText(content);
    toast.success(t("copied"));
  }, [content, t]);

  const handleDownload = useCallback(() => {
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${params.className}.h`;
    a.click();
    URL.revokeObjectURL(url);
  }, [content, params.className]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (!classInfo) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {t("failed_to_load_class")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-1 p-1 border-b shrink-0">
        <Button
          variant="ghost"
          size="sm"
          onClick={handleCopy}
          className="gap-1.5 h-7"
        >
          <Copy className="h-3.5 w-3.5" />
          {t("copy")}
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleDownload}
          className="gap-1.5 h-7"
        >
          <Download className="h-3.5 w-3.5" />
          {t("download")}
        </Button>
      </div>
      <div className="flex-1 min-h-0">
        <Editor
          height="100%"
          language="objective-c"
          value={content}
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
    </div>
  );
}

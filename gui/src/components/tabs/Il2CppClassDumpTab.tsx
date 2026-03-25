import { useCallback } from "react";
import type { IDockviewPanelProps } from "dockview";
import { Copy, Download, Loader2 } from "lucide-react";
import { toast } from "sonner";
import Editor from "@monaco-editor/react";

import { useTheme } from "@/components/providers/ThemeProvider";
import { Button } from "@/components/ui/button";
import { usePlatformQuery } from "@/lib/queries";

export function Il2CppClassDumpTab(
  props: IDockviewPanelProps<{ assemblyName: string; fullName: string }>,
) {
  const { assemblyName, fullName } = props.params;
  const { theme } = useTheme();

  const { data: source, isLoading } = usePlatformQuery(
    ["il2cpp", "classDump", assemblyName, fullName],
    (api) =>
      (api as any).il2cpp.classDump(assemblyName, fullName) as Promise<string>,
  );

  const handleCopy = useCallback(() => {
    if (source) {
      navigator.clipboard.writeText(source);
      toast.success("Copied");
    }
  }, [source]);

  const handleSave = useCallback(() => {
    if (!source) return;
    const blob = new Blob([source], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${fullName.replace(/\./g, "_")}.cs`;
    a.click();
    URL.revokeObjectURL(url);
  }, [source, fullName]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        Loading...
      </div>
    );
  }

  if (!source) {
    return (
      <div className="h-full flex items-center justify-center text-muted-foreground text-sm">
        Failed to dump class
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center gap-1 p-1 border-b shrink-0">
        <span className="text-xs text-muted-foreground flex-1 truncate font-mono px-2">
          {assemblyName} / {fullName}
        </span>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleCopy}
          className="gap-1.5 h-7"
        >
          <Copy className="h-3.5 w-3.5" />
          Copy
        </Button>
        <Button
          variant="ghost"
          size="sm"
          onClick={handleSave}
          className="gap-1.5 h-7"
        >
          <Download className="h-3.5 w-3.5" />
          Save
        </Button>
      </div>
      <div className="flex-1 min-h-0">
        <Editor
          height="100%"
          language="csharp"
          value={source}
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

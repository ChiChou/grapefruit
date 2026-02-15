import { useState, useCallback, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Download, Copy, Check, Play, Save } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import Editor, { type OnMount, type BeforeMount } from "@monaco-editor/react";

import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import { useTheme } from "@/components/theme-provider";
import { useRepl } from "@/context/useRepl";

async function loadFridaTypes(): Promise<Record<string, string>> {
  const res = await fetch("/api/d.ts/pack");
  if (!res.ok) throw new Error("Failed to load TypeScript definitions");
  return res.json();
}

export function CodeEditorTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { content, setContent, save, dirty } = useRepl();
  const [copied, setCopied] = useState(false);
  const { data: dts, isPending } = useQuery({
    queryKey: ["typescript"],
    queryFn: loadFridaTypes,
    retry: false,
  });

  const handleChange = useCallback(
    (value: string | undefined) => {
      if (value !== undefined) setContent(value);
    },
    [setContent],
  );

  const saveRef = useRef(save);
  saveRef.current = save;

  const handleBeforeMount = useCallback<BeforeMount>(
    (monaco) => {
      const jsDefaults = monaco.languages.typescript.javascriptDefaults;
      jsDefaults.setCompilerOptions({
        ...jsDefaults.getCompilerOptions(),
        target: monaco.languages.typescript.ScriptTarget.ESNext,
        lib: ["esnext"],
        allowJs: true,
        checkJs: false,
      });

      if (dts) {
        for (const [name, source] of Object.entries(dts)) {
          jsDefaults.addExtraLib(source, name);
        }
      }
    },
    [dts],
  );

  const monacoRef = useRef<Parameters<OnMount>[1] | null>(null);

  const handleEditorMount = useCallback<OnMount>((editor, monaco) => {
    monacoRef.current = monaco;

    editor.addAction({
      id: "save",
      label: "Save",
      keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS],
      run: () => saveRef.current(),
    });
  }, []);

  const handleDownload = useCallback(() => {
    const blob = new Blob([content], { type: "text/javascript" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "script.js";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [content]);

  const handleCopy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  }, [content]);

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between px-3 py-1.5 border-b bg-muted/30">
        <div className="flex items-center gap-1">
          <Button
            variant="default"
            size="sm"
            className="h-7 px-2 gap-1.5"
            disabled
          >
            <Play className="h-3.5 w-3.5" />
            {t("run")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 gap-1.5"
            onClick={save}
            disabled={!dirty}
          >
            <Save className="h-3.5 w-3.5" />
            {t("save")}
          </Button>
        </div>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 gap-1.5"
            onClick={handleDownload}
          >
            <Download className="h-3.5 w-3.5" />
            {t("repl_download")}
          </Button>
          <Button
            variant="ghost"
            size="sm"
            className="h-7 px-2 gap-1.5"
            onClick={handleCopy}
          >
            {copied ? (
              <>
                <Check className="h-3.5 w-3.5 text-green-500" />
                {t("copied")}
              </>
            ) : (
              <>
                <Copy className="h-3.5 w-3.5" />
                {t("repl_copy")}
              </>
            )}
          </Button>
        </div>
      </div>
      <div className="flex-1">
        {isPending ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner className="w-5 h-5" />
            <span>{t("loading")}...</span>
          </div>
        ) : (
          <Editor
            height="100%"
            language="javascript"
            value={content}
            onChange={handleChange}
            beforeMount={handleBeforeMount}
            onMount={handleEditorMount}
            theme={theme === "dark" ? "vs-dark" : "light"}
            options={{
              minimap: { enabled: false },
              scrollBeyondLastLine: false,
              wordWrap: "on",
              fontSize: 13,
              lineNumbers: "on",
              folding: true,
              automaticLayout: true,
              tabSize: 2,
              insertSpaces: true,
              formatOnPaste: true,
            }}
          />
        )}
      </div>
    </div>
  );
}

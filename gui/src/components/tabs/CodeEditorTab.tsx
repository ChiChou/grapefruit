import { useState, useCallback, useRef, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Download, Copy, Check, Play, Save } from "lucide-react";
import Editor, { type OnMount, type BeforeMount } from "@monaco-editor/react";

import { Button } from "@/components/ui/button";
import { useTheme } from "@/components/theme-provider";
import { useRepl } from "@/context/useRepl";

const FRIDA_DTS_URL =
  "https://cdn.jsdelivr.net/npm/@types/frida-gum/index.d.ts";

// todo:
// import following scripts under frida 17
//
// https://cdn.jsdelivr.net/npm/frida-objc-bridge/index.d.ts
// https://cdn.jsdelivr.net/npm/frida-java-bridge/index.d.ts
// https://cdn.jsdelivr.net/npm/frida-swift-bridge/dist/index.d.ts
//
// if frida version == 16, load a different version of @types/frida-gum
// https://cdn.jsdelivr.net/npm/@types/frida-gum@18/index.d.ts

let fridaTypes: string | null = null;
const fridaTypesPromise = fetch(FRIDA_DTS_URL)
  .then((r) => (r.ok ? r.text() : null))
  .then((text) => {
    fridaTypes = text;
    return text;
  })
  .catch(() => null);

export function CodeEditorTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { content, setContent, save, dirty } = useRepl();
  const [copied, setCopied] = useState(false);

  const handleChange = useCallback(
    (value: string | undefined) => {
      if (value !== undefined) setContent(value);
    },
    [setContent],
  );

  const saveRef = useRef(save);
  saveRef.current = save;

  const handleBeforeMount = useCallback<BeforeMount>((monaco) => {
    if (fridaTypes) {
      monaco.languages.typescript.javascriptDefaults.addExtraLib(
        fridaTypes,
        "frida-gum.d.ts",
      );
    }
  }, []);

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

  // If types arrive after mount, register them late
  useEffect(() => {
    if (fridaTypes || !monacoRef.current) return;
    fridaTypesPromise.then((text) => {
      if (text && monacoRef.current) {
        monacoRef.current.languages.typescript.javascriptDefaults.addExtraLib(
          text,
          "frida-gum.d.ts",
        );
      }
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
      </div>
    </div>
  );
}

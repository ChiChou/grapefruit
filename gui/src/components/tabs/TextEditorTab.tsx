import Editor, { loader } from "@monaco-editor/react";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { useTheme } from "@/components/theme-provider";
import { useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const LANGUAGES = [
  { value: "javascript", label: "JavaScript" },
  { value: "typescript", label: "TypeScript" },
  { value: "css", label: "CSS" },
  { value: "xml", label: "XML" },
  { value: "html", label: "HTML" },
  { value: "plaintext", label: "Plain Text" },
] as const;

loader.init().then((monaco) => {
  for (let i = 0; i < LANGUAGES.length; i++) {
    monaco.languages.register({ id: LANGUAGES[i].value });
  }
});

export interface TextEditorTabParams {
  path: string;
}

function guessLanguageFromName(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase();
  switch (ext) {
    case "js":
    case "mjs":
    case "cjs":
      return "javascript";
    case "ts":
    case "tsx":
      return "typescript";
    case "css":
      return "css";
    case "xml":
    case "html":
    case "htm":
      return "xml";
    default:
      return "plaintext";
  }
}

export function TextEditorTab({
  params,
}: IDockviewPanelProps<TextEditorTabParams>) {
  const { t } = useTranslation();
  const { api, status } = useSession();
  const { theme } = useTheme();
  const { openSingletonPanel } = useDock();
  const [content, setContent] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [isInvalidUtf8, setIsInvalidUtf8] = useState(false);
  const [selectedLanguage, setSelectedLanguage] = useState<string>("");

  const fullPath = params?.path || "";
  const guessedLanguage = guessLanguageFromName(fullPath);
  const language = selectedLanguage || guessedLanguage;

  const loadContent = useCallback(async () => {
    const apiReady = status === "ready" && !!api;
    if (!apiReady || !fullPath) return;

    setIsLoading(true);
    setError(null);
    setIsInvalidUtf8(false);

    try {
      const result = await api.fs.preview(fullPath);
      const uint8Array = new Uint8Array(result);

      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(
          uint8Array,
        );
        setContent(text);
      } catch {
        setContent(null);
        setIsInvalidUtf8(true);
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to load file");
      setContent(null);
    } finally {
      setIsLoading(false);
    }
  }, [api, status, fullPath]);

  useEffect(() => {
    loadContent();
  }, [loadContent]);

  const handleOpenInHexPreview = useCallback(() => {
    openSingletonPanel({
      id: `hexPreview-${fullPath}`,
      component: "hexPreview",
      title: fullPath.split("/").pop()!,
      params: { path: fullPath },
    });
  }, [fullPath, openSingletonPanel]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        {t("loading")}...
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {error}
      </div>
    );
  }

  if (isInvalidUtf8) {
    return (
      <div className="flex flex-col items-center justify-center h-full gap-4 p-8 text-center">
        <div className="text-destructive text-lg">{t("invalid_utf8_file")}</div>
        <div className="text-muted-foreground text-sm max-w-md">
          {t("invalid_utf8_description")}
        </div>
        <Button onClick={handleOpenInHexPreview}>
          {t("open_in_hex_preview")}
        </Button>
      </div>
    );
  }

  if (!content) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("no_content")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="flex-none px-4 py-2 bg-muted/50 border-b flex justify-between items-center gap-4">
        <span className="truncate">{fullPath}</span>
        <Select value={language} onValueChange={setSelectedLanguage}>
          <SelectTrigger className="w-40">
            <SelectValue />
          </SelectTrigger>
          <SelectContent>
            {LANGUAGES.map((lang) => (
              <SelectItem key={lang.value} value={lang.value}>
                {lang.label}
              </SelectItem>
            ))}
          </SelectContent>
        </Select>
      </div>
      <div className="flex-1 overflow-hidden">
        <Editor
          height="100%"
          language={language}
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

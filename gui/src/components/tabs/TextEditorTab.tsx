import Editor, { loader } from "@monaco-editor/react";
import type { IDockviewPanelProps } from "dockview";
import { Loader2 } from "lucide-react";
import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";

import { useTheme } from "@/components/providers/ThemeProvider";
import { Platform, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { useQuery } from "@tanstack/react-query";

const LANGUAGES = [
  { value: "javascript", label: "JavaScript", ext: ["js", "mjs", "cjs"] },
  { value: "typescript", label: "TypeScript", ext: ["ts", "tsx"] },
  { value: "css", label: "CSS", ext: ["css"] },
  { value: "html", label: "HTML", ext: ["html", "htm"] },
  { value: "xml", label: "XML", ext: ["xml"] },
  { value: "json", label: "JSON", ext: ["json", "jsonc", "jsonl"] },
  { value: "wasm", label: "WebAssembly", ext: ["wasm"] },
  { value: "kotlin", label: "Kotlin", ext: ["kt", "kts"] },
  { value: "java", label: "Java", ext: ["java"] },
  { value: "gradle", label: "Gradle", ext: ["gradle"] },
  { value: "smali", label: "Smali", ext: ["smali"] },
  { value: "swift", label: "Swift", ext: ["swift"] },
  { value: "objectivec", label: "Objective-C", ext: ["m", "mm"] },
  { value: "dart", label: "Dart", ext: ["dart"] },
  { value: "yaml", label: "YAML", ext: ["yml", "yaml"] },
  { value: "ini", label: "INI", ext: ["ini"] },
  { value: "toml", label: "TOML", ext: ["toml"] },
  { value: "lua", label: "Lua", ext: ["lua"] },
  { value: "python", label: "Python", ext: ["py", "pyw"] },
  { value: "protobuf", label: "Protocol Buffers", ext: ["proto", "textproto"] },
  { value: "shell", label: "Shell", ext: ["sh", "bash", "zsh"] },
  { value: "sql", label: "SQL", ext: ["sql"] },
  { value: "markdown", label: "Markdown", ext: ["md", "markdown"] },
  { value: "ruby", label: "Ruby", ext: ["rb"] },
  { value: "plaintext", label: "Plain Text", ext: ["txt", "text", "log"] },
];

const EXT_TO_LANG = new Map(
  LANGUAGES.flatMap((l) => l.ext.map((e) => [e, l.value])),
);

function langFromPath(path: string): string {
  const ext = path.split(".").pop()?.toLowerCase() ?? "";
  return EXT_TO_LANG.get(ext) ?? "plaintext";
}

export interface TextEditorTabParams {
  path: string;
}

export function TextEditorTab({
  params,
}: IDockviewPanelProps<TextEditorTabParams>) {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const { fruity, droid, platform } = useSession();
  const { openSingletonPanel } = useDock();
  const [content, setContent] = useState<string | null>(null);
  const [isInvalidUtf8, setIsInvalidUtf8] = useState(false);

  const fullPath = params?.path || "";
  const [selectedLanguage, setSelectedLanguage] = useState(() =>
    langFromPath(fullPath),
  );

  loader.init().then((monaco) => {
    for (let i = 0; i < LANGUAGES.length; i++) {
      monaco.languages.register({ id: LANGUAGES[i].value });
    }
  });

  const fs = (platform === Platform.Droid ? droid?.fs : fruity?.fs) ?? null;

  const {
    data: rawData,
    isLoading,
    error,
  } = useQuery<ArrayBuffer | null, Error>({
    queryKey: ["filePreview", fullPath],
    queryFn: () => fs!.preview(fullPath),
    enabled: !!fs && !!fullPath,
    staleTime: 0,
    gcTime: 0,
  });

  useEffect(() => {
    if (!rawData) return;

    const processData = () => {
      const u8 = new Uint8Array(rawData);

      try {
        const text = new TextDecoder("utf-8", { fatal: true }).decode(u8);
        setContent(text);
        setIsInvalidUtf8(false);
      } catch {
        setContent(null);
        setIsInvalidUtf8(true);
      }
    };

    processData();
  }, [rawData]);

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
        {(error as Error).message}
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
        <span className="truncate text-sm">{fullPath}</span>
        <Select
          value={selectedLanguage}
          onValueChange={(v) => {
            if (v) setSelectedLanguage(v);
          }}
        >
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
          language={selectedLanguage}
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

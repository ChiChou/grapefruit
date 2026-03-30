import Editor, { loader, type OnMount } from "@monaco-editor/react";
import type { IDockviewPanelProps } from "dockview";
import {
  ClipboardCopy,
  ClipboardPaste,
  Download,
  FoldVertical,
  Loader2,
  Redo,
  Save,
  Scissors,
  Search,
  Undo,
  UnfoldVertical,
  WrapText,
} from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { useTranslation } from "react-i18next";
import type { editor } from "monaco-editor";

import { useTheme } from "@/components/providers/ThemeProvider";
import { Platform, useSession } from "@/context/SessionContext";
import { useDock } from "@/context/DockContext";
import { Button } from "@/components/ui/button";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
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
  { value: "xml", label: "XML (plist)", ext: ["plist"] },
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
  writable?: boolean;
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
  const [wordWrap, setWordWrap] = useState(true);
  const [dirty, setDirty] = useState(false);
  const editorRef = useRef<editor.IStandaloneCodeEditor | null>(null);
  const savedContentRef = useRef<string>("");

  const fullPath = params?.path || "";
  const writable = params?.writable ?? false;
  const fileName = fullPath.split("/").pop() ?? "file";
  const [selectedLanguage, setSelectedLanguage] = useState(() =>
    langFromPath(fullPath),
  );

  loader.init().then((monaco) => {
    for (let i = 0; i < LANGUAGES.length; i++) {
      monaco.languages.register({ id: LANGUAGES[i].value });
    }
  });

  const fs = (platform === Platform.Droid ? droid?.fs : fruity?.fs) ?? null;

  const onMount: OnMount = useCallback(
    (ed, monaco) => {
      editorRef.current = ed;
      if (writable) {
        ed.addAction({
          id: "save",
          label: "Save",
          keybindings: [monaco.KeyMod.CtrlCmd | monaco.KeyCode.KeyS],
          run: () => save(),
        });
        ed.onDidChangeModelContent(() => {
          setDirty(ed.getValue() !== savedContentRef.current);
        });
      }
    },
    [writable],
  );

  const run = useCallback((id: string) => {
    editorRef.current?.getAction(id)?.run();
  }, []);

  const save = useCallback(async () => {
    if (!fs || !writable) return;
    const text = editorRef.current?.getValue() ?? "";
    await fs.saveText(fullPath, text);
    savedContentRef.current = text;
    setDirty(false);
  }, [fs, writable, fullPath]);

  const download = useCallback(() => {
    const text = editorRef.current?.getValue() ?? content ?? "";
    const blob = new Blob([text], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = fileName;
    a.click();
    URL.revokeObjectURL(a.href);
  }, [content, fileName]);

  const cut = useCallback(() => {
    const ed = editorRef.current;
    if (!ed) return;
    const sel = ed.getSelection();
    if (sel && !sel.isEmpty()) {
      const text = ed.getModel()?.getValueInRange(sel) ?? "";
      navigator.clipboard.writeText(text);
      ed.executeEdits("cut", [{ range: sel, text: "" }]);
    }
  }, []);

  const copy = useCallback(() => {
    const ed = editorRef.current;
    if (!ed) return;
    const sel = ed.getSelection();
    if (sel && !sel.isEmpty()) {
      const text = ed.getModel()?.getValueInRange(sel) ?? "";
      navigator.clipboard.writeText(text);
    }
  }, []);

  const paste = useCallback(async () => {
    const ed = editorRef.current;
    if (!ed) return;
    const text = await navigator.clipboard.readText();
    ed.trigger("paste", "type", { text });
  }, []);

  const toggleWrap = useCallback(() => {
    setWordWrap((v) => {
      const next = !v;
      editorRef.current?.updateOptions({ wordWrap: next ? "on" : "off" });
      return next;
    });
  }, []);

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
        savedContentRef.current = text;
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

  const ico = "size-3.5";

  const tb = (
    tip: string,
    icon: React.ReactNode,
    action: () => void,
    opts?: { active?: boolean; disabled?: boolean; label?: string },
  ) => (
    <Tooltip>
      <TooltipTrigger
        render={
          <Button
            variant="ghost"
            className={`h-7 px-1.5 gap-1 text-xs ${opts?.active ? "bg-accent" : ""} ${opts?.label ? "" : "w-7"}`}
            disabled={opts?.disabled}
            onClick={action}
          />
        }
      >
        {icon}
        {opts?.label && <span>{opts.label}</span>}
      </TooltipTrigger>
      <TooltipContent side="bottom" className="text-xs">
        {tip}
      </TooltipContent>
    </Tooltip>
  );

  const sep = <Separator orientation="vertical" className="h-4 mx-0.5" />;

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="flex-none h-8 px-1.5 bg-muted/50 border-b flex items-center gap-0.5">
        {tb("Save", <Save className={ico} />, save, { disabled: !writable || !dirty, label: "Save" })}
        {sep}
        {tb("Undo", <Undo className={ico} />, () => run("undo"), { disabled: !writable })}
        {tb("Redo", <Redo className={ico} />, () => run("redo"), { disabled: !writable })}
        {sep}
        {tb("Cut", <Scissors className={ico} />, cut, { disabled: !writable })}
        {tb("Copy", <ClipboardCopy className={ico} />, copy)}
        {tb("Paste", <ClipboardPaste className={ico} />, paste, { disabled: !writable })}
        {sep}
        {tb("Find", <Search className={ico} />, () => run("actions.find"), { label: "Find" })}
        {sep}
        {tb("Fold All", <FoldVertical className={ico} />, () => run("editor.foldAll"))}
        {tb("Unfold All", <UnfoldVertical className={ico} />, () => run("editor.unfoldAll"))}
        {sep}
        {tb("Word Wrap", <WrapText className={ico} />, toggleWrap, { active: wordWrap })}
        <div className="flex-1" />
        {tb("Download", <Download className={ico} />, download, { label: "Download" })}
      </div>
      <div className="flex-1 overflow-hidden">
        <Editor
          height="100%"
          language={selectedLanguage}
          defaultValue={content}
          theme={theme === "dark" ? "vs-dark" : "light"}
          onMount={onMount}
          options={{
            readOnly: !writable,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: wordWrap ? "on" : "off",
            fontSize: 13,
            lineNumbers: "on",
            folding: true,
            automaticLayout: true,
          }}
        />
      </div>
      <div className="flex-none h-6 px-2 bg-muted/50 border-t flex items-center justify-between text-[11px] text-muted-foreground">
        <span className="truncate">{fullPath}</span>
        <Select
          value={selectedLanguage}
          onValueChange={(v) => {
            if (v) setSelectedLanguage(v);
          }}
        >
          <SelectTrigger className="h-5 border-none bg-transparent shadow-none text-[11px] text-muted-foreground px-1.5 gap-1">
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
    </div>
  );
}

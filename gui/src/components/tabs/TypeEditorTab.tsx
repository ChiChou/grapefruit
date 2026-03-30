import { useCallback, useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { Loader2, AlertCircle, Plus, Play } from "lucide-react";
import Editor from "@monaco-editor/react";
import { useR2Session } from "@/lib/use-r2-session";
import { useTheme } from "@/components/providers/ThemeProvider";
import { Button } from "@/components/ui/button";
import {
  ResizablePanelGroup,
  ResizablePanel,
  ResizableHandle,
} from "@/components/ui/resizable";

interface TypeDef {
  name: string;
  kind: "struct" | "enum" | "typedef";
  size?: number;
}

export function TypeEditorTab(_props: IDockviewPanelProps) {
  const { t } = useTranslation();
  const { cmd, isReady, error: sessionError } = useR2Session();
  const { theme } = useTheme();
  const [types, setTypes] = useState<TypeDef[]>([]);
  const [selected, setSelected] = useState<string | null>(null);
  const [editorVal, setEditorVal] = useState("");
  const [loading, setLoading] = useState(true);
  const [applying, setApplying] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; msg: string } | null>(null);

  const loadTypes = useCallback(async () => {
    if (!isReady) return;
    setLoading(true);
    try {
      const [tsRaw, teRaw] = await Promise.all([cmd("tsj"), cmd("tej")]);
      const list: TypeDef[] = [];

      try {
        const structs = JSON.parse(tsRaw);
        if (Array.isArray(structs)) {
          for (const s of structs) {
            list.push({
              name: typeof s === "string" ? s : (s.name ?? ""),
              kind: "struct",
              size: typeof s === "object" ? s.size : undefined,
            });
          }
        }
      } catch {}

      try {
        const enums = JSON.parse(teRaw);
        if (Array.isArray(enums)) {
          for (const e of enums) {
            list.push({
              name: typeof e === "string" ? e : (e.name ?? ""),
              kind: "enum",
            });
          }
        }
      } catch {}

      setTypes(list);
    } catch {}
    setLoading(false);
  }, [cmd, isReady]);

  useEffect(() => { loadTypes(); }, [loadTypes]);

  const showType = useCallback(async (name: string, kind: string) => {
    setSelected(name);
    setResult(null);
    try {
      const raw = kind === "enum" ? await cmd(`te ${name}`) : await cmd(`ts ${name}`);
      setEditorVal(raw.trim());
    } catch {
      setEditorVal("");
    }
  }, [cmd]);

  const applyType = useCallback(async () => {
    if (!editorVal.trim()) return;
    setApplying(true);
    setResult(null);
    try {
      for (const line of editorVal.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && !trimmed.startsWith("//")) {
          await cmd(`"td ${trimmed}"`);
        }
      }
      setResult({ ok: true, msg: t("r2_type_applied") });
      loadTypes();
    } catch (e) {
      setResult({ ok: false, msg: e instanceof Error ? e.message : String(e) });
    } finally {
      setApplying(false);
    }
  }, [cmd, editorVal, loadTypes, t]);

  const newType = () => {
    setSelected(null);
    setEditorVal("struct MyStruct {\n  int field1;\n  char *field2;\n};");
    setResult(null);
  };

  if (sessionError) {
    return (
      <div className="flex items-center justify-center h-full">
        <div className="flex flex-col items-center gap-2 text-center">
          <AlertCircle className="h-6 w-6 text-destructive" />
          <p className="text-xs font-mono">{sessionError}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col">
      <ResizablePanelGroup orientation="horizontal" className="flex-1">
        <ResizablePanel id="type-list" defaultSize="30%" minSize="20%">
          <div className="h-full flex flex-col">
            <div className="flex items-center gap-1 px-2 py-1 border-b">
              <span className="text-xs text-muted-foreground font-medium flex-1">{t("r2_types")} ({types.length})</span>
              <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={newType}>
                <Plus className="h-3.5 w-3.5" />
              </Button>
            </div>
            {loading ? (
              <div className="flex items-center justify-center flex-1 text-muted-foreground">
                <Loader2 className="h-4 w-4 animate-spin" />
              </div>
            ) : (
              <div className="flex-1 overflow-auto">
                {types.map((t) => (
                  <div
                    key={`${t.kind}-${t.name}`}
                    className={`px-3 py-1.5 text-xs font-mono cursor-pointer border-b border-border/30 hover:bg-accent/30 flex items-center gap-2 ${
                      selected === t.name ? "bg-primary/10" : ""
                    }`}
                    onClick={() => showType(t.name, t.kind)}
                  >
                    <span className={`text-[9px] px-1 rounded ${
                      t.kind === "struct" ? "bg-blue-500/20 text-blue-400" : "bg-green-500/20 text-green-400"
                    }`}>
                      {t.kind}
                    </span>
                    <span className="truncate">{t.name}</span>
                    {t.size != null && (
                      <span className="text-muted-foreground ml-auto shrink-0">{t.size}B</span>
                    )}
                  </div>
                ))}
                {types.length === 0 && (
                  <div className="flex items-center justify-center h-20 text-xs text-muted-foreground">
                    {t("r2_no_types")}
                  </div>
                )}
              </div>
            )}
          </div>
        </ResizablePanel>

        <ResizableHandle />

        <ResizablePanel id="type-editor" defaultSize="70%" minSize="40%">
          <div className="h-full flex flex-col">
            <div className="flex items-center gap-2 px-2 py-1 border-b">
              <span className="text-xs font-mono flex-1 truncate">
                {selected ?? t("r2_new_type")}
              </span>
              <Button
                variant="default"
                size="sm"
                className="h-6 text-xs gap-1"
                disabled={applying || !editorVal.trim()}
                onClick={applyType}
              >
                {applying ? <Loader2 className="h-3 w-3 animate-spin" /> : <Play className="h-3 w-3" />}
                {t("r2_apply")}
              </Button>
            </div>
            {result && (
              <div className={`px-3 py-1 text-xs ${result.ok ? "text-green-400" : "text-destructive"}`}>
                {result.msg}
              </div>
            )}
            <div className="flex-1">
              <Editor
                height="100%"
                language="c"
                theme={theme === "dark" ? "vs-dark" : "light"}
                value={editorVal}
                onChange={(v) => setEditorVal(v ?? "")}
                options={{
                  minimap: { enabled: false },
                  fontSize: 12,
                  fontFamily: "ui-monospace, SFMono-Regular, 'SF Mono', Menlo, Consolas, monospace",
                  lineNumbers: "on",
                  scrollBeyondLastLine: false,
                }}
              />
            </div>
          </div>
        </ResizablePanel>
      </ResizablePanelGroup>
    </div>
  );
}

import { useEffect, useState } from "react";
import { AlertCircle, Loader2 } from "lucide-react";
import Editor from "@monaco-editor/react";
import { useTheme } from "@/components/providers/ThemeProvider";
import { Button } from "@/components/ui/button";

export function Decompiler({ load, live = false, engine = "Kuna" }: { load: (signal: AbortSignal) => Promise<string>; live?: boolean; engine?: "Kuna" | "DDC" }) {
  const { theme } = useTheme();
  const [code, setCode] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const abort = new AbortController();
    setLoading(true);
    setCode("");
    setError("");
    load(abort.signal).then((value) => {
      if (!abort.signal.aborted) setCode(value);
    }).catch((error: unknown) => {
      if (!abort.signal.aborted) setError(error instanceof Error ? error.message : String(error));
    }).finally(() => { if (!abort.signal.aborted) setLoading(false); });
    return () => abort.abort();
  }, [load, attempt]);
  if (loading) return <div className="flex h-full items-center justify-center text-muted-foreground"><Loader2 className="mr-2 h-4 w-4 animate-spin" />Decompiling with {engine}…</div>;
  if (error) return <div className="flex h-full flex-col items-center justify-center gap-3 p-6 text-center"><AlertCircle className="h-6 w-6 text-destructive" /><p className="text-sm break-all">{error}</p><Button variant="outline" onClick={() => setAttempt((n) => n + 1)}>Retry</Button></div>;
  return <div className="flex h-full flex-col">
    {live && <p className="border-b px-3 py-2 text-xs text-muted-foreground">Live function snapshot. External data and callee type information may be unavailable.</p>}
    {engine === "DDC" && <p className="border-b px-3 py-2 text-xs text-muted-foreground">Java source for the selected method’s class.</p>}
    <div className="min-h-0 flex-1"><Editor height="100%" language={engine === "DDC" ? "java" : "c"} theme={theme === "dark" ? "vs-dark" : "light"} value={code} options={{ readOnly: true, minimap: { enabled: false }, fontSize: 13, scrollBeyondLastLine: false, wordWrap: "on" }} /></div>
  </div>;
}

import { useState, useEffect, useRef } from "react";
import { useTranslation } from "react-i18next";
import { Plus, X, Loader2 } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { useSession, Platform } from "@/context/SessionContext";
import * as signatures from "@/lib/signatures";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const NATIVE_TYPES = signatures.types;

const ARG_TYPES = NATIVE_TYPES.filter((t) => t !== "void");

interface NativeHookDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  functionName: string;
  modulePath: string | null;
  onConfirm: (sig: { args: string[]; returns: string }) => void;
}

export function NativeHookDialog({
  open,
  onOpenChange,
  functionName,
  modulePath,
  onConfirm,
}: NativeHookDialogProps) {
  const { t } = useTranslation();
  const [args, setArgs] = useState<string[]>([]);
  const [returns, setReturns] = useState("void");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [template, setTemplate] = useState<signatures.Template | null>(null);
  const [rawArgs, setRawArgs] = useState<string[]>([]);
  const dirty = useRef(false);
  const { platform, fruity, droid } = useSession();
  const api = platform === Platform.Droid ? droid : fruity;

  useEffect(() => {
    if (!open) return;
    const abort = new AbortController();
    dirty.current = false;
    setArgs([]);
    setRawArgs([]);
    setReturns("void");
    setTemplate(null);
    setError(null);
    setLoading(true);
    async function load() {
      try {
        const info = await Promise.race([
          api?.info.processInfo().catch(() => undefined) ?? Promise.resolve(undefined),
          new Promise<undefined>((resolve) => setTimeout(resolve, 1500)),
        ]);
        abort.signal.throwIfAborted();
        if (!platform) return;
        const match = await signatures.lookup(platform === Platform.Droid ? "android" : "darwin", functionName, modulePath, info?.arch, abort.signal);
        if (abort.signal.aborted) return;
        setTemplate(match);
        if (match && !dirty.current) {
          setArgs(match.args.map(signatures.display));
          setRawArgs(match.args.map((arg) => arg.c));
          setReturns(signatures.display(match.returns));
        }
      } catch (error) {
        if (!abort.signal.aborted) setError(error instanceof Error ? error.message : String(error));
      } finally {
        if (!abort.signal.aborted) setLoading(false);
      }
    }
    void load();
    return () => abort.abort();
  }, [open, platform, api, functionName, modulePath]);

  const addParam = () => {
    dirty.current = true;
    setArgs((prev) => [...prev, "pointer"]);
    setRawArgs((prev) => [...prev, ""]);
  };

  const removeParam = (index: number) => {
    dirty.current = true;
    setArgs((prev) => prev.filter((_, i) => i !== index));
    setRawArgs((prev) => prev.filter((_, i) => i !== index));
  };

  const updateParam = (index: number, value: string) => {
    dirty.current = true;
    setArgs((prev) => prev.map((v, i) => (i === index ? value : v)));
  };

  const handleConfirm = () => {
    onConfirm({ args, returns });
    onOpenChange(false);
  };

  const label = modulePath ? `${modulePath}!${functionName}` : functionName;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-lg">
        <DialogHeader>
          <DialogTitle className="font-mono text-sm break-all">
            {label}
          </DialogTitle>
          <DialogDescription>
            {t(
              "hook_native_dialog_desc",
              "Configure parameter types for this native function hook.",
            )}
          </DialogDescription>
        </DialogHeader>

        <div className="space-y-4">
          {loading ? (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Looking up offline template…
            </div>
          ) : (
            <p className="text-xs text-muted-foreground">
              {error ?? (template
                ? `Template from ${template.source}${template.nameOnly ? " (matched by symbol name)" : ""}. Review and edit the types below.`
                : "No known signature. Enter the types below.")}
              {template?.variadic && " Variadic function: add any additional arguments you want to log."}
              {template && (template.returns.approximate || template.args.some((arg) => arg.approximate)) && " Some types are approximate."}
            </p>
          )}

          {/* Return type */}
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium w-20 shrink-0">Returns</span>
            <Select
              value={returns}
              onValueChange={(v) => { if (v !== null) { dirty.current = true; setReturns(v); } }}
            >
              <SelectTrigger className="font-mono text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {NATIVE_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t === "char *" ? "pointer → UTF-8 string" : t === "id" ? "pointer → ObjC object" : t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {template && <p className="text-xs font-mono text-muted-foreground">C return: {template.returns.c}</p>}

          {/* Arguments */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">Arguments</span>
              <Button
                variant="outline"
                size="sm"
                onClick={addParam}
                className="gap-1 h-7"
              >
                <Plus className="h-3.5 w-3.5" />
                Add param
              </Button>
            </div>

            {args.length === 0 && (
              <p className="text-xs text-muted-foreground">No parameters</p>
            )}

            {args.map((arg, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground w-8 shrink-0 text-right">
                  #{i}
                </span>
                <Select
                  value={arg}
                  onValueChange={(v) => v !== null && updateParam(i, v)}
                >
                  <SelectTrigger className="font-mono text-xs" title={rawArgs[i] || undefined}>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ARG_TYPES.map((t) => (
                      <SelectItem key={t} value={t}>
                        {t === "char *" ? "pointer → UTF-8 string" : t === "id" ? "pointer → ObjC object" : t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {rawArgs[i] && <span className="max-w-40 truncate text-xs font-mono text-muted-foreground" title={rawArgs[i]}>{rawArgs[i]}</span>}
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 shrink-0"
                  onClick={() => removeParam(i)}
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>
        </div>

        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            Dismiss
          </Button>
          <Button onClick={handleConfirm}>
            Confirm
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

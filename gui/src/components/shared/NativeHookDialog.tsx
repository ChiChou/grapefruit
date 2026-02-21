import { useState, useEffect, useCallback } from "react";
import { useTranslation } from "react-i18next";
import { Plus, X, Loader2, Sparkles } from "lucide-react";

import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
} from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

const NATIVE_TYPES = [
  "void *",
  "int",
  "uint",
  "long",
  "float",
  "double",
  "bool",
  "char *",
  "id",
  "void",
] as const;

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
  const [llmError, setLlmError] = useState<string | null>(null);

  const queryLLM = useCallback(async () => {
    setLoading(true);
    setLlmError(null);

    const prompt = `Give me the argument types of function ${functionName}, return in format like
{"args":["void *", "int"], "returns": "void *"}

Do not include qualifiers. My program can only handle few native types:
"void *", "int", "uint", "long", "float", "double", "bool", "char *", "id", "void"

please normalize type to those. if a type is an Objective-C class or instance, use "id".

only the json part, without any descriptions. if this function is not in your knowledge, return

{"error": "unknown function"}

do not make up or guess`;

    const res = await fetch("/api/llm", {
      method: "POST",
      body: prompt,
    }).catch(() => null);

    if (!res) {
      setLlmError(t("llm_query_failed", "Failed to query LLM"));
      setLoading(false);
      return;
    }

    if (!res.ok) {
      setLlmError(
        res.status === 500
          ? t("llm_not_configured", "LLM not configured")
          : t("llm_request_failed", "LLM request failed"),
      );
      setLoading(false);
      return;
    }

    const text = await res.text();

    const jsonMatch = text.match(/\{[\s\S]*\}/);
    if (!jsonMatch) {
      setLlmError(t("llm_invalid_response", "Invalid response from LLM"));
      setLoading(false);
      return;
    }

    let data: Record<string, unknown>;
    try {
      data = JSON.parse(jsonMatch[0]);
    } catch {
      setLlmError(t("llm_invalid_response", "Invalid response from LLM"));
      setLoading(false);
      return;
    }

    if (Array.isArray(data.args)) {
      setArgs(data.args as string[]);
    }
    if (data.returns) {
      setReturns(data.returns as string);
    }
    setLoading(false);
  }, [functionName, t]);

  // Auto-query LLM when dialog opens
  useEffect(() => {
    if (open) {
      setArgs([]);
      setReturns("void");
      setLlmError(null);
      queryLLM();
    }
  }, [open, queryLLM]);

  const addParam = () => {
    setArgs((prev) => [...prev, "void *"]);
  };

  const removeParam = (index: number) => {
    setArgs((prev) => prev.filter((_, i) => i !== index));
  };

  const updateParam = (index: number, value: string) => {
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
          {/* LLM status */}
          {loading && (
            <div className="flex items-center gap-2 text-sm text-muted-foreground">
              <Loader2 className="h-4 w-4 animate-spin" />
              Querying AI for function signature...
            </div>
          )}
          {llmError && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-muted-foreground">{llmError}</span>
              <Button
                variant="ghost"
                size="sm"
                onClick={queryLLM}
                disabled={loading}
                className="gap-1"
              >
                <Sparkles className="h-3.5 w-3.5" />
                Retry
              </Button>
            </div>
          )}

          {/* Return type */}
          <div className="flex items-center gap-2">
            <span className="text-sm font-medium w-20 shrink-0">Returns</span>
            <Select
              value={returns}
              onValueChange={(v) => v !== null && setReturns(v)}
            >
              <SelectTrigger className="font-mono text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {NATIVE_TYPES.map((t) => (
                  <SelectItem key={t} value={t}>
                    {t}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

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
                  <SelectTrigger className="font-mono text-xs">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    {ARG_TYPES.map((t) => (
                      <SelectItem key={t} value={t}>
                        {t}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
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
          <Button onClick={handleConfirm} disabled={loading}>
            Confirm
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

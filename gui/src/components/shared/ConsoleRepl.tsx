import {
  useState,
  useRef,
  useCallback,
  useEffect,
  forwardRef,
  useImperativeHandle,
} from "react";
import { Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import JsonTreeView from "./JsonTreeView";

export interface ConsoleReplHandle {
  clear: () => void;
}

interface ConsoleReplProps {
  onEvaluate: (input: string) => Promise<unknown>;
  placeholder?: string;
}

interface ReplEntry {
  id: number;
  input: string;
  status: "loading" | "success" | "error";
  result?: unknown;
  error?: string;
}

let nextId = 0;

const ConsoleRepl = forwardRef<ConsoleReplHandle, ConsoleReplProps>(
  function ConsoleRepl({ onEvaluate, placeholder = "Expression..." }, ref) {
    const [entries, setEntries] = useState<ReplEntry[]>([]);
    const [input, setInput] = useState("");
    const [historyIndex, setHistoryIndex] = useState(-1);
    const historyRef = useRef<string[]>([]);
    const scrollRef = useRef<HTMLDivElement>(null);
    const inputRef = useRef<HTMLInputElement>(null);

    useImperativeHandle(ref, () => ({
      clear() {
        setEntries([]);
      },
    }));

    // Auto-scroll to bottom on new entries
    useEffect(() => {
      const el = scrollRef.current;
      if (el) el.scrollTop = el.scrollHeight;
    }, [entries]);

    const submit = useCallback(
      async (expr: string) => {
        const trimmed = expr.trim();
        if (!trimmed) return;

        historyRef.current.push(trimmed);
        setHistoryIndex(-1);
        setInput("");

        const id = nextId++;
        const entry: ReplEntry = { id, input: trimmed, status: "loading" };
        setEntries((prev) => [...prev, entry]);

        try {
          const result = await onEvaluate(trimmed);
          setEntries((prev) =>
            prev.map((e) =>
              e.id === id ? { ...e, status: "success", result } : e,
            ),
          );
        } catch (err) {
          setEntries((prev) =>
            prev.map((e) =>
              e.id === id
                ? {
                    ...e,
                    status: "error",
                    error: err instanceof Error ? err.message : String(err),
                  }
                : e,
            ),
          );
        }
      },
      [onEvaluate],
    );

    const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
      if (e.key === "Enter") {
        e.preventDefault();
        submit(input);
        return;
      }

      const history = historyRef.current;
      if (e.key === "ArrowUp") {
        e.preventDefault();
        if (history.length === 0) return;
        const next =
          historyIndex === -1 ? history.length - 1 : Math.max(0, historyIndex - 1);
        setHistoryIndex(next);
        setInput(history[next]);
      } else if (e.key === "ArrowDown") {
        e.preventDefault();
        if (historyIndex === -1) return;
        const next = historyIndex + 1;
        if (next >= history.length) {
          setHistoryIndex(-1);
          setInput("");
        } else {
          setHistoryIndex(next);
          setInput(history[next]);
        }
      }
    };

    return (
      <div className="h-full flex flex-col">
        {/* Toolbar */}
        <div className="flex items-center justify-end px-2 py-1 border-b">
          <Button
            variant="ghost"
            size="icon"
            className="h-6 w-6"
            onClick={() => setEntries([])}
            title="Clear console"
          >
            <Trash2 className="h-3 w-3" />
          </Button>
        </div>

        {/* History */}
        <div ref={scrollRef} className="flex-1 overflow-y-auto px-3 py-2">
          {entries.map((entry) => (
            <div key={entry.id} className="mb-2">
              <div className="font-mono text-[11px] text-muted-foreground">
                <span className="text-blue-500 dark:text-blue-400 mr-1">
                  &gt;
                </span>
                {entry.input}
              </div>
              <div className="pl-4 mt-0.5">
                {entry.status === "loading" && (
                  <Spinner className="h-3 w-3" />
                )}
                {entry.status === "error" && (
                  <span className="font-mono text-[11px] text-red-600 dark:text-red-400">
                    {entry.error}
                  </span>
                )}
                {entry.status === "success" && (
                  <ReplResult value={entry.result} />
                )}
              </div>
            </div>
          ))}
        </div>

        {/* Input */}
        <div className="flex items-center border-t px-3 py-1.5 gap-2">
          <span className="font-mono text-[11px] text-blue-500 dark:text-blue-400 shrink-0">
            &gt;
          </span>
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => {
              setInput(e.target.value);
              setHistoryIndex(-1);
            }}
            onKeyDown={handleKeyDown}
            placeholder={placeholder}
            className="flex-1 bg-transparent font-mono text-[11px] outline-none placeholder:text-muted-foreground"
            autoFocus
          />
        </div>
      </div>
    );
  },
);

function ReplResult({ value }: { value: unknown }) {
  if (value === undefined) {
    return (
      <span className="font-mono text-[11px] text-muted-foreground">
        undefined
      </span>
    );
  }
  if (value !== null && typeof value === "object") {
    return <JsonTreeView value={value} defaultExpanded={2} />;
  }
  // Inline primitive
  return (
    <div className="font-mono text-[11px]">
      <InlineValue value={value} />
    </div>
  );
}

function InlineValue({ value }: { value: unknown }) {
  if (value === null) {
    return <span className="text-muted-foreground">null</span>;
  }
  switch (typeof value) {
    case "string":
      return (
        <span className="text-emerald-600 dark:text-emerald-400">
          &quot;{value}&quot;
        </span>
      );
    case "number":
      return <span className="text-sky-600 dark:text-sky-400">{value}</span>;
    case "boolean":
      return (
        <span className="text-amber-600 dark:text-amber-400">
          {String(value)}
        </span>
      );
    default:
      return <span className="text-muted-foreground">{String(value)}</span>;
  }
}

export default ConsoleRepl;

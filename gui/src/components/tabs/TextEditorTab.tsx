import { useCallback, useEffect, useState } from "react";
import type { IDockviewPanelProps } from "dockview";
import { useSession } from "@/context/SessionContext";
import { Loader2 } from "lucide-react";

export interface TextEditorTabParams {
  path: string;
}

function getLanguageFromPath(path: string): string {
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

function highlightCode(code: string, language: string): string {
  const html = code
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");

  if (language === "plaintext") {
    return `<pre class="text-foreground whitespace-pre-wrap">${html}</pre>`;
  }

  const patterns: Record<string, Array<[RegExp, string]>> = {
    javascript: [
      [/\/\/.*$/gm, "text-gray-500"],
      [/\/\*[\s\S]*?\*\//g, "text-gray-500"],
      [/\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|this|class|extends|import|export|from|default|async|await|try|catch|throw|typeof|instanceof|in|of|delete|void|null|undefined|true|false)\b/g, "text-purple-400"],
      [/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "text-green-400"],
      [/\b\d+\b/g, "text-orange-400"],
      [/\b[A-Z_][a-zA-Z0-9_]*\b/g, "text-yellow-300"],
      [/[{}()\[\];]/g, "text-yellow-300"],
    ],
    typescript: [
      [/\/\/.*$/gm, "text-gray-500"],
      [/\/\*[\s\S]*?\*\//g, "text-gray-500"],
      [/\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|this|class|extends|import|export|from|default|async|await|try|catch|throw|typeof|instanceof|in|of|delete|void|null|undefined|true|false|interface|type|enum|implements|private|public|protected|static|readonly|abstract|namespace|module|declare|as)\b/g, "text-purple-400"],
      [/"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*'|`(?:[^`\\]|\\.)*`/g, "text-green-400"],
      [/\b\d+\b/g, "text-orange-400"],
      [/\b[A-Z_][a-zA-Z0-9_]*\b/g, "text-yellow-300"],
      [/[{}()\[\];]/g, "text-yellow-300"],
      [/:[ \t]*(string|number|boolean|null|undefined|any|void|never|unknown|object|Array<[^>]+>|\[[^\]]*\]|{[^{}]*})/g, "text-blue-300"],
    ],
    css: [
      [/\/\*[\s\S]*?\*\//g, "text-gray-500"],
      [/[#.](?:[\w-]+)/g, "text-yellow-300"],
    ],
    xml: [
      [/<!--[\s\S]*?-->/g, "text-gray-500"],
      [/<(?:\/?)([\w-]+)([^>]*)?>/g, "text-purple-400"],
      [/ ([^=]+)=/g, "text-blue-300"],
    ],
  };

  const langPatterns = patterns[language] || [];

  let highlighted = html;
  for (const [regex, className] of langPatterns) {
    highlighted = highlighted.replace(regex, (match) => `<span class="${className}">${match}</span>`);
  }

  return `<pre class="text-foreground whitespace-pre-wrap">${highlighted}</pre>`;
}

export function TextEditorTab({ params }: IDockviewPanelProps<TextEditorTabParams>) {
  const { api, status } = useSession();
  const [content, setContent] = useState<string | null>(null);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fullPath = params?.path || "";
  const language = getLanguageFromPath(fullPath);

  const apiReady = status === "ready" && !!api;

  const loadContent = useCallback(async () => {
    if (!apiReady || !fullPath) return;

    setIsLoading(true);
    setError(null);

    try {
      const result = await api.fs.preview(fullPath);
      const uint8Array = new Uint8Array(result);
      const text = new TextDecoder("utf-8", { fatal: true }).decode(uint8Array);
      setContent(text);
    } catch (err) {
      try {
        const result = await api.fs.preview(fullPath);
        const uint8Array = new Uint8Array(result);
        const text = new TextDecoder("utf-8", { fatal: false }).decode(uint8Array);
        setContent(text);
      } catch {
        setError(err instanceof Error ? err.message : "Failed to load file");
        setContent(null);
      }
    } finally {
      setIsLoading(false);
    }
  }, [api, apiReady, fullPath]);

  useEffect(() => {
    loadContent();
  }, [loadContent]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="w-6 h-6 animate-spin mr-2" />
        Loading...
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

  if (!content) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        No content
      </div>
    );
  }

  const highlightedContent = highlightCode(content, language);

  return (
    <div className="h-full flex flex-col bg-background">
      <div className="flex-none px-4 py-2 bg-muted/50 border-b flex justify-between items-center">
        <span className="truncate">{fullPath}</span>
        <span className="text-xs text-muted-foreground ml-4 px-2 py-1 bg-muted rounded">
          {language}
        </span>
      </div>
      <div className="flex-1 overflow-auto p-4">
        <div
          className="font-mono text-sm leading-6"
          dangerouslySetInnerHTML={{ __html: highlightedContent }}
        />
      </div>
    </div>
  );
}

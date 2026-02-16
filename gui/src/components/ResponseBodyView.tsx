import { useMemo } from "react";
import { useQuery } from "@tanstack/react-query";
import Editor from "@monaco-editor/react";

import { useTheme } from "@/components/theme-provider";
import HexView from "@/components/HexView";

function mimeToLanguage(mime: string | undefined): string | null {
  if (!mime) return null;
  const lower = mime.toLowerCase().split(";")[0].trim();
  if (lower.includes("json")) return "json";
  if (lower.includes("xml") || lower.includes("svg")) return "xml";
  if (lower.includes("html")) return "html";
  if (lower.includes("css")) return "css";
  if (lower.includes("javascript") || lower.includes("ecmascript"))
    return "javascript";
  if (lower.includes("typescript")) return "typescript";
  if (lower.includes("yaml") || lower.includes("yml")) return "yaml";
  if (lower.includes("text/plain")) return "plaintext";
  if (lower.includes("x-plist")) return "xml";
  return null;
}

function isImageMime(mime: string | undefined): boolean {
  if (!mime) return false;
  return mime.toLowerCase().startsWith("image/");
}

function tryDecodeUtf8(buf: ArrayBuffer): string | null {
  try {
    const decoder = new TextDecoder("utf-8", { fatal: true });
    return decoder.decode(buf);
  } catch {
    return null;
  }
}

export function ResponseBodyView({
  url,
  mime,
}: {
  url: string;
  mime: string | undefined;
}) {
  const { theme } = useTheme();

  const { data, isLoading, error } = useQuery<{
    text: string | null;
    bytes: Uint8Array;
  }>({
    queryKey: ["responseBody", url],
    queryFn: async () => {
      const res = await fetch(url);
      if (!res.ok) throw new Error(`Failed to fetch: ${res.status}`);
      const buf = await res.arrayBuffer();
      return { text: tryDecodeUtf8(buf), bytes: new Uint8Array(buf) };
    },
    staleTime: Infinity,
    gcTime: 5 * 60 * 1000,
    enabled: !isImageMime(mime),
  });

  const language = useMemo(() => mimeToLanguage(mime), [mime]);

  if (isImageMime(mime)) {
    return (
      <img
        src={url}
        alt="Response body"
        className="max-w-full max-h-96 object-contain rounded border"
      />
    );
  }

  if (isLoading)
    return (
      <span className="text-xs text-muted-foreground">Loading body...</span>
    );

  if (error)
    return (
      <span className="text-xs text-red-500">
        Failed to load body: {(error as Error).message}
      </span>
    );

  if (!data) return null;

  // Binary data — not valid UTF-8
  if (data.text === null) {
    return (
      <div className="h-full border rounded overflow-hidden">
        <HexView data={data.bytes} stride={16} />
      </div>
    );
  }

  // Valid UTF-8 with a known language — Monaco editor
  if (language) {
    return (
      <div className="border rounded overflow-hidden h-full">
        <Editor
          height="100%"
          language={language}
          value={data.text}
          theme={theme === "dark" ? "vs-dark" : "light"}
          options={{
            readOnly: true,
            minimap: { enabled: false },
            scrollBeyondLastLine: false,
            wordWrap: "on",
            fontSize: 12,
            lineNumbers: "on",
            folding: true,
            contextmenu: false,
            domReadOnly: true,
          }}
        />
      </div>
    );
  }

  // Fallback: plain text
  return (
    <pre className="text-xs font-mono whitespace-pre-wrap break-all max-h-96 overflow-auto">
      {data.text}
    </pre>
  );
}

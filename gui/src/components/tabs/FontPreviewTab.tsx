import { useCallback, useEffect, useState, useRef } from "react";
import { Italic, Bold, Underline, Loader2 } from "lucide-react";
import type { IDockviewPanelProps } from "dockview";
import { useTranslation } from "react-i18next";

import { ToggleGroup, ToggleGroupItem } from "@/components/ui/toggle-group";
import { Slider } from "@/components/ui/slider";
import { useSession } from "@/context/SessionContext";

export interface FontPreviewTabParams {
  path: string;
}

const KEY_TEXT = "font_preview_text";
const KEY_SIZE = "font_preview_size";

export function FontPreviewTab({
  params,
}: IDockviewPanelProps<FontPreviewTabParams>) {
  const { pid, device } = useSession();
  const { t } = useTranslation();

  const fullPath = params?.path || "";
  const fontUrl = `/api/download/${device}/${pid}?path=${encodeURIComponent(fullPath)}`;

  const [isLoading, setIsLoading] = useState(true);
  const [hasError, setHasError] = useState(false);
  const [isItalic, setIsItalic] = useState(false);
  const [isBold, setIsBold] = useState(false);
  const [isUnderline, setIsUnderline] = useState(false);
  const [fontSize, setFontSize] = useState(() => {
    const saved = localStorage.getItem(KEY_SIZE);
    return saved ? Number(saved) : 32;
  });
  const contentRef = useRef<HTMLDivElement>(null);

  const previewText =
    localStorage.getItem(KEY_TEXT) ||
    "The quick brown fox jumps over the lazy dog";

  useEffect(() => {
    let cancelled = false;
    let loadedFace: FontFace | null = null;

    const loadFont = async () => {
      setHasError(false);
      setIsLoading(true);
      try {
        const fontFace = new FontFace("PreviewFont", `url('${fontUrl}')`);
        await fontFace.load();
        if (cancelled) return;
        document.fonts.add(fontFace);
        loadedFace = fontFace;
      } catch (e) {
        if (cancelled) return;
        console.error("Failed to load font preview", e);
        setHasError(true);
      } finally {
        if (!cancelled) setIsLoading(false);
      }
    };

    loadFont();

    return () => {
      cancelled = true;
      if (loadedFace) document.fonts.delete(loadedFace);
    };
  }, [fontUrl]);

  useEffect(() => {
    if (!contentRef.current) return;

    const observer = new MutationObserver(() => {
      const text = contentRef.current?.textContent || "";
      localStorage.setItem(KEY_TEXT, text);
    });

    observer.observe(contentRef.current, {
      characterData: true,
      childList: true,
      subtree: true,
    });

    return () => observer.disconnect();
  }, []);

  const handlePaste = useCallback((e: React.ClipboardEvent) => {
    e.preventDefault();
    const plain = e.clipboardData.getData("text/plain");
    const selection = getSelection();
    if (!selection?.rangeCount) return;

    const range = selection.getRangeAt(0);
    range.deleteContents();

    const textNode = document.createTextNode(plain);
    range.insertNode(textNode);
    range.setStartAfter(textNode);
    range.collapse(true);

    selection.removeAllRanges();
    selection.addRange(range);
  }, []);

  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    if (e.ctrlKey || e.metaKey) {
      switch (e.key.toLowerCase()) {
        case "b":
        case "i":
        case "u":
          e.preventDefault();
          return;
      }
    }
  }, []);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
        {t("loading")}
      </div>
    );
  }

  if (hasError) {
    return (
      <div className="flex items-center justify-center h-full text-destructive">
        {t("failed_to_load_font_preview")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col p-4">
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <ToggleGroup
          className="rounded-md border"
          value={[
            ...(isBold ? ["bold"] : []),
            ...(isItalic ? ["italic"] : []),
            ...(isUnderline ? ["underline"] : []),
          ]}
          onValueChange={(values) => {
            setIsBold(values.includes("bold"));
            setIsItalic(values.includes("italic"));
            setIsUnderline(values.includes("underline"));
          }}
        >
          <ToggleGroupItem
            value="bold"
            aria-label="Toggle bold"
            className="px-2 py-1 text-xs transition-colors rounded-none first:rounded-l-md last:rounded-r-md aria-pressed:bg-primary aria-pressed:text-primary-foreground"
          >
            <Bold size="14" />
          </ToggleGroupItem>
          <ToggleGroupItem
            value="italic"
            aria-label="Toggle italic"
            className="px-2 py-1 text-xs transition-colors rounded-none first:rounded-l-md last:rounded-r-md aria-pressed:bg-primary aria-pressed:text-primary-foreground"
          >
            <Italic size="14" />
          </ToggleGroupItem>
          <ToggleGroupItem
            value="underline"
            aria-label="Toggle underline"
            className="px-2 py-1 text-xs transition-colors rounded-none first:rounded-l-md last:rounded-r-md aria-pressed:bg-primary aria-pressed:text-primary-foreground"
          >
            <Underline size="14" />
          </ToggleGroupItem>
        </ToggleGroup>
        <Slider
          value={[fontSize]}
          min={12}
          max={200}
          step={1}
          className="w-32"
          onValueChange={(value) => {
            const arr = Array.isArray(value) ? value : [value];
            const newSize = arr[0];
            setFontSize(newSize);
            localStorage.setItem(KEY_SIZE, newSize.toString());
          }}
        />
        <span className="text-sm w-12">{fontSize}px</span>
      </div>
      <div
        ref={contentRef}
        contentEditable
        suppressContentEditableWarning
        onPaste={handlePaste}
        onKeyDown={handleKeyDown}
        className="flex-1 flex items-center justify-center outline-none text-center wrap-break-word px-4"
        style={{
          fontFamily: "'PreviewFont', sans-serif",
          fontSize: `${fontSize}px`,
          fontStyle: isItalic ? "italic" : "normal",
          fontWeight: isBold ? "bold" : "normal",
          textDecoration: isUnderline ? "underline" : "none",
          userSelect: "text",
          cursor: "text",
        }}
      >
        {previewText}
      </div>
    </div>
  );
}

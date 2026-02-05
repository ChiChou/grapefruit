import { useState, useCallback, useRef } from "react";
import { useTranslation } from "react-i18next";
import { toast } from "sonner";
import { Plus, X, Download, Copy, FileCode, Check, Play } from "lucide-react";
import Editor from "@monaco-editor/react";

import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { useTheme } from "@/components/theme-provider";
import { useRepl } from "@/context/ReplContext";
import { cn } from "@/lib/utils";

export function CodeEditorTab() {
  const { t } = useTranslation();
  const { theme } = useTheme();
  const {
    documents,
    activeDocId,
    addDocument,
    removeDocument,
    updateDocument,
    renameDocument,
    setActiveDocument,
  } = useRepl();

  const [editingId, setEditingId] = useState<string | null>(null);
  const [editingName, setEditingName] = useState("");
  const [copied, setCopied] = useState(false);
  const inputRef = useRef<HTMLInputElement>(null);

  const activeDocument = documents.find((doc) => doc.id === activeDocId);

  const handleNewDocument = useCallback(() => {
    addDocument();
  }, [addDocument]);

  const handleRemoveDocument = useCallback(
    (id: string, e: React.MouseEvent) => {
      e.stopPropagation();
      removeDocument(id);
    },
    [removeDocument],
  );

  const handleEditorChange = useCallback(
    (value: string | undefined) => {
      if (activeDocId && value !== undefined) {
        updateDocument(activeDocId, value);
      }
    },
    [activeDocId, updateDocument],
  );

  const handleStartRename = useCallback(
    (id: string, name: string, e: React.MouseEvent) => {
      e.stopPropagation();
      setEditingId(id);
      setEditingName(name);
      // Focus input after state update
      setTimeout(() => inputRef.current?.focus(), 0);
    },
    [],
  );

  const handleFinishRename = useCallback(() => {
    if (editingId && editingName.trim()) {
      renameDocument(editingId, editingName.trim());
    }
    setEditingId(null);
    setEditingName("");
  }, [editingId, editingName, renameDocument]);

  const handleRenameKeyDown = useCallback(
    (e: React.KeyboardEvent) => {
      if (e.key === "Enter") {
        handleFinishRename();
      } else if (e.key === "Escape") {
        setEditingId(null);
        setEditingName("");
      }
    },
    [handleFinishRename],
  );

  const handleDownload = useCallback(() => {
    if (!activeDocument) return;

    const blob = new Blob([activeDocument.content], {
      type: "text/javascript",
    });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = activeDocument.name.endsWith(".js")
      ? activeDocument.name
      : `${activeDocument.name}.js`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, [activeDocument]);

  const handleCopy = useCallback(async () => {
    if (!activeDocument) return;

    try {
      await navigator.clipboard.writeText(activeDocument.content);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error("Failed to copy:", err);
    }
  }, [activeDocument]);

  const handleRun = useCallback(() => {
    toast.info(t("feature_coming_soon"));
  }, [t]);

  return (
    <div className="h-full flex">
      {/* Document List Sidebar */}
      <div className="w-48 border-r flex flex-col bg-muted/30">
        <div className="p-2 border-b">
          <Button
            variant="outline"
            size="sm"
            className="w-full justify-start gap-2"
            onClick={handleNewDocument}
          >
            <Plus className="h-4 w-4" />
            {t("repl_new_document")}
          </Button>
        </div>
        <div className="flex-1 overflow-auto p-1">
          {documents.length === 0 ? (
            <div className="text-xs text-muted-foreground text-center py-4">
              {t("no_results")}
            </div>
          ) : (
            <div className="space-y-0.5">
              {documents.map((doc) => (
                <div
                  key={doc.id}
                  className={cn(
                    "group flex items-center gap-1.5 px-2 py-1.5 rounded-md cursor-pointer text-sm transition-colors",
                    doc.id === activeDocId
                      ? "bg-accent text-accent-foreground"
                      : "hover:bg-muted",
                  )}
                  onClick={() => setActiveDocument(doc.id)}
                >
                  <FileCode className="h-3.5 w-3.5 shrink-0 text-muted-foreground" />
                  {editingId === doc.id ? (
                    <Input
                      ref={inputRef}
                      value={editingName}
                      onChange={(e) => setEditingName(e.target.value)}
                      onBlur={handleFinishRename}
                      onKeyDown={handleRenameKeyDown}
                      className="h-5 px-1 py-0 text-xs"
                      onClick={(e) => e.stopPropagation()}
                    />
                  ) : (
                    <span
                      className="flex-1 truncate"
                      onDoubleClick={(e) =>
                        handleStartRename(
                          doc.id,
                          doc.name,
                          e as unknown as React.MouseEvent,
                        )
                      }
                      title={doc.name}
                    >
                      {doc.name}
                    </span>
                  )}
                  <Button
                    variant="ghost"
                    size="icon"
                    className="h-5 w-5 opacity-0 group-hover:opacity-100 transition-opacity"
                    onClick={(e) => handleRemoveDocument(doc.id, e)}
                  >
                    <X className="h-3 w-3" />
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* Editor Area */}
      <div className="flex-1 flex flex-col">
        {activeDocument ? (
          <>
            <div className="flex items-center justify-between px-3 py-1.5 border-b bg-muted/30">
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium truncate">
                  {activeDocument.name}
                </span>
                <Button
                  variant="default"
                  size="sm"
                  className="h-7 px-2 gap-1.5"
                  onClick={handleRun}
                >
                  <Play className="h-3.5 w-3.5" />
                </Button>
              </div>
              <div className="flex items-center gap-1">
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 gap-1.5"
                  onClick={handleDownload}
                >
                  <Download className="h-3.5 w-3.5" />
                  {t("repl_download")}
                </Button>
                <Button
                  variant="ghost"
                  size="sm"
                  className="h-7 px-2 gap-1.5"
                  onClick={handleCopy}
                >
                  {copied ? (
                    <>
                      <Check className="h-3.5 w-3.5 text-green-500" />
                      {t("copied")}
                    </>
                  ) : (
                    <>
                      <Copy className="h-3.5 w-3.5" />
                      {t("repl_copy")}
                    </>
                  )}
                </Button>
              </div>
            </div>
            <div className="flex-1">
              <Editor
                height="100%"
                language="javascript"
                value={activeDocument.content}
                onChange={handleEditorChange}
                theme={theme === "dark" ? "vs-dark" : "light"}
                options={{
                  minimap: { enabled: false },
                  scrollBeyondLastLine: false,
                  wordWrap: "on",
                  fontSize: 13,
                  lineNumbers: "on",
                  folding: true,
                  automaticLayout: true,
                  tabSize: 2,
                  insertSpaces: true,
                  formatOnPaste: true,
                }}
              />
            </div>
          </>
        ) : (
          <div className="flex-1 flex items-center justify-center text-muted-foreground">
            <div className="text-center">
              <FileCode className="h-12 w-12 mx-auto mb-2 opacity-50" />
              <p className="text-sm">{t("repl_new_document")}</p>
              <Button
                variant="outline"
                size="sm"
                className="mt-2"
                onClick={handleNewDocument}
              >
                <Plus className="h-4 w-4 mr-1" />
                {t("repl_new_document")}
              </Button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

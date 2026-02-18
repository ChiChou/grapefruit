import { useState, useRef, useEffect, useCallback } from "react";
import { useTranslation } from "react-i18next";
import {
  Folder,
  File,
  Download,
  Pencil,
  Trash2,
  SquareArrowOutUpRight,
  FileText,
  Binary,
  Database,
  FileJson,
  FileImage,
  Type,
  Check,
  X,
  Loader2,
} from "lucide-react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { MetaData } from "@agent/fruity/modules/fs";
import { formatSize, formatDate, typeFor } from "../../lib/file-explorer.ts";

interface FileTableProps {
  items: MetaData[];
  isLoading: boolean;
  cwd: string;
  onDownload: (fileName: string) => void;
  onPreview: (fileName: string, type: string) => void;
  onRename: (oldName: string, newName: string) => Promise<void>;
  onDelete: (fileName: string) => Promise<void>;
}

export function FileTable({
  items,
  isLoading,
  cwd,
  onDownload,
  onPreview,
  onRename,
  onDelete,
}: FileTableProps) {
  const { t } = useTranslation();
  const [editingFile, setEditingFile] = useState<string | null>(null);
  const [editValue, setEditValue] = useState("");
  const [isRenaming, setIsRenaming] = useState(false);
  const [deletingFile, setDeletingFile] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  // Preserve scroll position across dockview tab switches.
  // Dockview hides inactive panels with display:none which resets scrollTop.
  const scrollTopRef = useRef(0);
  const observerRef = useRef<IntersectionObserver | null>(null);

  useEffect(() => {
    scrollTopRef.current = 0;
  }, [cwd]);

  const scrollContainerRef = useCallback((el: HTMLDivElement | null) => {
    if (observerRef.current) {
      observerRef.current.disconnect();
      observerRef.current = null;
    }
    if (!el) return;

    el.addEventListener(
      "scroll",
      () => {
        scrollTopRef.current = el.scrollTop;
      },
      { passive: true },
    );

    observerRef.current = new IntersectionObserver((entries) => {
      if (entries[0]?.isIntersecting && scrollTopRef.current > 0) {
        el.scrollTop = scrollTopRef.current;
      }
    });
    observerRef.current.observe(el);

    if (scrollTopRef.current > 0) {
      requestAnimationFrame(() => {
        el.scrollTop = scrollTopRef.current;
      });
    }
  }, []);

  // Focus input when editing starts
  useEffect(() => {
    if (editingFile && inputRef.current) {
      inputRef.current.focus();
      // Select filename without extension
      const dotIndex = editValue.lastIndexOf(".");
      if (dotIndex > 0) {
        inputRef.current.setSelectionRange(0, dotIndex);
      } else {
        inputRef.current.select();
      }
    }
  }, [editingFile, editValue]);

  const startEditing = (fileName: string) => {
    setEditingFile(fileName);
    setEditValue(fileName);
  };

  const cancelEditing = () => {
    setEditingFile(null);
    setEditValue("");
  };

  const confirmRename = async () => {
    if (!editingFile || !editValue.trim() || editValue === editingFile) {
      cancelEditing();
      return;
    }

    setIsRenaming(true);
    try {
      await onRename(editingFile, editValue.trim());
      setEditingFile(null);
      setEditValue("");
    } catch (err) {
      console.error("Failed to rename:", err);
    } finally {
      setIsRenaming(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") {
      e.preventDefault();
      confirmRename();
    } else if (e.key === "Escape") {
      e.preventDefault();
      cancelEditing();
    }
  };

  const handleDelete = async (fileName: string) => {
    setDeletingFile(fileName);
    try {
      await onDelete(fileName);
    } catch (err) {
      console.error("Failed to delete:", err);
    } finally {
      setDeletingFile(null);
    }
  };

  if (isLoading) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          {t("loading")}...
        </div>
        {cwd && (
          <div className="px-2 py-1 text-xs text-muted-foreground border-t">{cwd}</div>
        )}
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex items-center justify-center text-muted-foreground">
          {t("empty_directory")}
        </div>
        {cwd && (
          <div className="px-2 py-1 text-xs text-muted-foreground border-t">{cwd}</div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div ref={scrollContainerRef} className="flex-1 overflow-auto">
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead className="w-8"></TableHead>
              <TableHead>{t("name")}</TableHead>
              <TableHead className="w-32"></TableHead>
              <TableHead className="w-24 text-right">{t("size")}</TableHead>
              <TableHead className="w-48">{t("modified")}</TableHead>
              <TableHead className="w-4"></TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {items.map((item) => {
              const isEditing = editingFile === item.name;
              const isDeleting = deletingFile === item.name;

              return (
                <TableRow key={item.name} className="group">
                  <TableCell>
                    {item.dir ? (
                      <Folder className="w-4 h-4 text-yellow-500" />
                    ) : (
                      <File className="w-4 h-4 text-muted-foreground" />
                    )}
                  </TableCell>
                  <TableCell className="font-mono text-sm">
                    {isEditing ? (
                      <div className="flex items-center gap-1">
                        <Input
                          ref={inputRef}
                          value={editValue}
                          onChange={(e) => setEditValue(e.target.value)}
                          onKeyDown={handleKeyDown}
                          className="h-7 text-sm font-mono"
                          disabled={isRenaming}
                        />
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-green-600 shrink-0"
                          onClick={confirmRename}
                          disabled={isRenaming}
                          title={t("confirm")}
                        >
                          {isRenaming ? (
                            <Loader2 className="h-4 w-4 animate-spin" />
                          ) : (
                            <Check className="h-4 w-4" />
                          )}
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 shrink-0"
                          onClick={cancelEditing}
                          disabled={isRenaming}
                          title={t("cancel")}
                        >
                          <X className="h-4 w-4" />
                        </Button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onPreview(item.name, typeFor(item.name))}
                        className="hover:text-amber-600 dark:hover:text-amber-400 hover:underline"
                      >
                        {item.name}
                      </button>
                    )}
                  </TableCell>
                  <TableCell>
                    {!isEditing && (
                      <div className="flex gap-1">
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                          onClick={() => onDownload(item.name)}
                          title={t("download")}
                        >
                          <Download className="h-4 w-4" />
                        </Button>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                          onClick={() => startEditing(item.name)}
                          title={t("rename")}
                        >
                          <Pencil className="h-4 w-4" />
                        </Button>
                        <DropdownMenu>
                          <DropdownMenuTrigger render={<Button variant="ghost" size="icon" className="h-7 w-7 text-destructive hover:text-destructive" title={t("delete")} disabled={isDeleting} />}>
                              {isDeleting ? (
                                <Loader2 className="h-4 w-4 animate-spin" />
                              ) : (
                                <Trash2 className="h-4 w-4" />
                              )}
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="start">
                            <DropdownMenuItem
                              onClick={() => handleDelete(item.name)}
                              className="text-destructive focus:text-destructive"
                            >
                              {t("delete")}
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </div>
                    )}
                  </TableCell>
                  <TableCell className="text-right text-sm">
                    {item.dir ? "-" : formatSize(item.size)}
                  </TableCell>
                  <TableCell className="text-sm text-muted-foreground">
                    {formatDate(item.created)}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger render={<Button variant="ghost" size="icon" className="h-7 w-7" title={t("open_with")} />}>
                          <SquareArrowOutUpRight className="h-4 w-4" />
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="start">
                        <DropdownMenuItem
                          onClick={() => onPreview(item.name, "text")}
                        >
                          <FileText className="mr-2 h-4 w-4" />
                          {t("text_editor")}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => onPreview(item.name, "hex")}
                        >
                          <Binary className="mr-2 h-4 w-4" />
                          {t("hex_view")}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => onPreview(item.name, "sqlite")}
                        >
                          <Database className="mr-2 h-4 w-4" />
                          {t("sqlite_editor")}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => onPreview(item.name, "image")}
                        >
                          <FileImage className="mr-2 h-4 w-4" />
                          {t("image_preview")}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => onPreview(item.name, "plist")}
                        >
                          <FileJson className="mr-2 h-4 w-4" />
                          {t("plist_preview")}
                        </DropdownMenuItem>
                        <DropdownMenuItem
                          onClick={() => onPreview(item.name, "font")}
                        >
                          <Type className="mr-2 h-4 w-4" />
                          {t("font_preview")}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              );
            })}
          </TableBody>
        </Table>
      </div>
      {cwd && (
        <div className="px-2 py-1 text-xs text-muted-foreground border-t shrink-0">
          {cwd}
        </div>
      )}
    </div>
  );
}

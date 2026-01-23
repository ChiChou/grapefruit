import { useTranslation } from "react-i18next";
import {
  Folder,
  File,
  Download,
  Pencil,
  Trash2,
  SquareArrowOutUpRight,
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import type { MetaData } from "../../../../agent/types/fruity/modules/fs.ts";
import { formatSize, formatDate, typeFor } from "../../lib/file-explorer.ts";

interface FileTableProps {
  items: MetaData[];
  isLoading: boolean;
  cwd: string;
  onDownload: (fileName: string) => void;
  onPreview: (fileName: string, type: string) => void;
}

export function FileTable({
  items,
  isLoading,
  cwd,
  onDownload,
  onPreview,
}: FileTableProps) {
  const { t } = useTranslation();

  if (isLoading) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex items-center justify-center text-gray-500">
          {t("loading")}...
        </div>
        {cwd && (
          <div className="px-2 py-1 text-xs text-gray-500 border-t">{cwd}</div>
        )}
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex flex-col h-full">
        <div className="flex-1 flex items-center justify-center text-gray-500">
          {t("empty_directory")}
        </div>
        {cwd && (
          <div className="px-2 py-1 text-xs text-gray-500 border-t">{cwd}</div>
        )}
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full">
      <div className="flex-1 overflow-auto">
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
            {items.map((item) => (
              <TableRow key={item.name} className="group">
                <TableCell>
                  {item.dir ? (
                    <Folder className="w-4 h-4 text-yellow-500" />
                  ) : (
                    <File className="w-4 h-4 text-gray-500" />
                  )}
                </TableCell>
                <TableCell className="font-mono text-sm">
                  <button
                    type="button"
                    onClick={() => onPreview(item.name, typeFor(item.name))}
                    className="hover:text-blue-600 dark:hover:text-blue-400 hover:underline"
                  >
                    {item.name}
                  </button>
                </TableCell>
                <TableCell>
                  <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      onClick={() => onDownload(item.name)}
                      title={t("download")}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7"
                      title={t("rename")}
                    >
                      <Pencil className="h-4 w-4" />
                    </Button>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 text-destructive hover:text-destructive"
                      title={t("delete")}
                    >
                      <Trash2 className="h-4 w-4" />
                    </Button>
                  </div>
                </TableCell>
                <TableCell className="text-right text-sm">
                  {item.dir ? "-" : formatSize(item.size)}
                </TableCell>
                <TableCell className="text-sm text-gray-500">
                  {formatDate(item.created)}
                </TableCell>
                <TableCell>
                  <DropdownMenu>
                    <DropdownMenuTrigger asChild>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7"
                        title={t("open_with")}
                      >
                        <SquareArrowOutUpRight className="h-4 w-4" />
                      </Button>
                    </DropdownMenuTrigger>
                    <DropdownMenuContent align="start">
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "text")}
                      >
                        {t("text_editor")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "hex")}
                      >
                        {t("hex_view")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "sqlite")}
                      >
                        {t("sqlite_editor")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "image")}
                      >
                        {t("image_preview")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "plist")}
                      >
                        {t("plist_preview")}
                      </DropdownMenuItem>
                      <DropdownMenuItem
                        onClick={() => onPreview(item.name, "font")}
                      >
                        {t("font_preview")}
                      </DropdownMenuItem>
                    </DropdownMenuContent>
                  </DropdownMenu>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      </div>
      {cwd && (
        <div className="px-2 py-1 text-xs text-gray-500 border-t shrink-0">
          {cwd}
        </div>
      )}
    </div>
  );
}

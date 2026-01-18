import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";
import { File, Folder, Pencil, Download, Trash2 } from "lucide-react";
import { Button } from "@/components/ui/button";

import { ConnectionStatus, useSession } from "@/context/SessionContext";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";

import type { MetaData } from "../../../../agent/types/fruity/modules/fs";

export interface FinderTabParams {
  path: string;
}

function formatSize(size: number | null): string {
  if (size === null) return "-";
  if (size < 1024) return `${size} B`;
  if (size < 1024 * 1024) return `${(size / 1024).toFixed(1)} KB`;
  if (size < 1024 * 1024 * 1024)
    return `${(size / (1024 * 1024)).toFixed(1)} MB`;
  return `${(size / (1024 * 1024 * 1024)).toFixed(1)} GB`;
}

function formatDate(date: Date): string {
  return new Date(date).toLocaleString();
}

export function FinderTab({ params }: IDockviewPanelProps<FinderTabParams>) {
  const { api, status } = useSession();
  const { t } = useTranslation();
  const [isLoading, setIsLoading] = useState(false);
  const [items, setItems] = useState<MetaData[]>([]);

  useEffect(() => {
    if (status !== ConnectionStatus.Ready || !api) return;

    setIsLoading(true);
    api.fs
      .ls(params.path)
      .then((result) => {
        const data = result.filter((e) => !e.dir);
        data.sort((a, b) => a.name.localeCompare(b.name));
        setItems(data);
      })
      .catch((err) => {
        console.error("Failed to load directory:", err);
        setItems([]);
      })
      .finally(() => setIsLoading(false));
  }, [api, status, params.path]);

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("loading")}...
      </div>
    );
  }

  if (items.length === 0) {
    return (
      <div className="flex items-center justify-center h-full text-gray-500">
        {t("empty_directory")}
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col overflow-auto">
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8"></TableHead>
            <TableHead>{t("name")}</TableHead>
            <TableHead className="w-32"></TableHead>
            <TableHead className="w-24 text-right">{t("size")}</TableHead>
            <TableHead className="w-48">{t("modified")}</TableHead>
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
              <TableCell className="font-mono text-sm">{item.name}</TableCell>
              <TableCell>
                <div className="flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity">
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
                    className="h-7 w-7"
                    title={t("download")}
                  >
                    <Download className="h-4 w-4" />
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
            </TableRow>
          ))}
        </TableBody>
      </Table>
    </div>
  );
}

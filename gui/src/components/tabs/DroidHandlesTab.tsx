import { useMemo, useRef, useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
import { Spinner } from "@/components/ui/spinner";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { ArrowDown, ArrowUp, ArrowUpDown, RefreshCw } from "lucide-react";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { useDroidRpcQuery } from "@/lib/queries";

import type {
  FileDescriptor,
  TcpEntry,
  UdpEntry,
  FileEntry,
} from "@agent/droid/modules/lsof";

function isTcp(fd: FileDescriptor): fd is TcpEntry {
  return fd.type === "tcp" || fd.type === "tcp6";
}

function isUdp(fd: FileDescriptor): fd is UdpEntry {
  return fd.type === "udp" || fd.type === "udp6";
}

function isFile(fd: FileDescriptor): fd is FileEntry {
  return fd.type === "file";
}

function getDetails(handle: FileDescriptor): string {
  if (isTcp(handle))
    return `${handle.localIp}:${handle.localPort} → ${handle.remoteIp}:${handle.remotePort} (${handle.state})`;
  if (isUdp(handle))
    return `${handle.localIp}:${handle.localPort} → ${handle.remoteIp}:${handle.remotePort}`;
  if (isFile(handle)) return handle.path;
  return "";
}

type SortKey = "fd" | "type" | "details";
type SortOrder = "asc" | "desc";

export function DroidHandlesTab() {
  const { t } = useTranslation();
  const [sortKey, setSortKey] = useState<SortKey>("fd");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");
  const [reloadInterval, setReloadInterval] = useState(0);
  const [showTcp, setShowTcp] = useState(true);
  const [showUdp, setShowUdp] = useState(true);
  const [showFile, setShowFile] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const {
    data: handles = [],
    isLoading,
    refetch,
  } = useDroidRpcQuery<FileDescriptor[]>(
    ["droidHandles"],
    (api) => api.lsof.fds(),
  );

  useEffect(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    if (reloadInterval > 0) {
      intervalRef.current = setInterval(() => refetch(), reloadInterval * 1000);
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [reloadInterval, refetch]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortOrder("asc");
    }
  };

  const filteredAndSortedHandles = useMemo(() => {
    return handles
      .filter((handle) => {
        if (isTcp(handle) && !showTcp) return false;
        if (isUdp(handle) && !showUdp) return false;
        if (isFile(handle) && !showFile) return false;
        return true;
      })
      .sort((a, b) => {
        let cmp = 0;
        switch (sortKey) {
          case "fd":
            cmp = (a.fd ?? -1) - (b.fd ?? -1);
            break;
          case "type":
            cmp = a.type.localeCompare(b.type);
            break;
          case "details":
            cmp = getDetails(a).localeCompare(getDetails(b));
            break;
        }
        return sortOrder === "asc" ? cmp : -cmp;
      });
  }, [handles, sortKey, sortOrder, showTcp, showUdp, showFile]);

  const SortIcon = ({ column }: { column: SortKey }) => {
    if (sortKey !== column) return <ArrowUpDown className="h-4 w-4 ml-1" />;
    return sortOrder === "asc" ? (
      <ArrowUp className="h-4 w-4 ml-1" />
    ) : (
      <ArrowDown className="h-4 w-4 ml-1" />
    );
  };

  return (
    <div className="h-full flex flex-col">
      <div className="flex items-center justify-between p-4">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2">
            <Checkbox
              id="filter-tcp"
              checked={showTcp}
              onCheckedChange={(checked) => setShowTcp(checked === true)}
            />
            <Label htmlFor="filter-tcp" className="text-sm cursor-pointer">
              TCP
            </Label>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="filter-udp"
              checked={showUdp}
              onCheckedChange={(checked) => setShowUdp(checked === true)}
            />
            <Label htmlFor="filter-udp" className="text-sm cursor-pointer">
              UDP
            </Label>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="filter-file"
              checked={showFile}
              onCheckedChange={(checked) => setShowFile(checked === true)}
            />
            <Label htmlFor="filter-file" className="text-sm cursor-pointer">
              File
            </Label>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <Select
            value={String(reloadInterval)}
            onValueChange={(value) => setReloadInterval(Number(value))}
          >
            <SelectTrigger className="w-28 h-8 text-xs">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="0">{t("never")}</SelectItem>
              <SelectItem value="5">{t("5s")}</SelectItem>
              <SelectItem value="10">{t("10s")}</SelectItem>
              <SelectItem value="60">{t("1min")}</SelectItem>
            </SelectContent>
          </Select>
          <Button
            variant="outline"
            size="sm"
            onClick={() => refetch()}
            disabled={isLoading}
          >
            <RefreshCw
              className={`h-4 w-4 mr-2 ${isLoading ? "animate-spin" : ""}`}
            />
            {t("reload")}
          </Button>
        </div>
      </div>
      <div className="flex-1 overflow-auto border-t border-border">
        {isLoading && handles.length === 0 ? (
          <div className="flex items-center justify-center h-full gap-2 text-muted-foreground">
            <Spinner />
            {t("loading")}...
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead
                  className="w-16 cursor-pointer select-none hover:bg-accent"
                  onClick={() => handleSort("fd")}
                >
                  <div className="flex items-center">
                    {t("file_descriptor")}
                    <SortIcon column="fd" />
                  </div>
                </TableHead>
                <TableHead
                  className="w-24 cursor-pointer select-none hover:bg-accent"
                  onClick={() => handleSort("type")}
                >
                  <div className="flex items-center">
                    {t("type")}
                    <SortIcon column="type" />
                  </div>
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none hover:bg-accent"
                  onClick={() => handleSort("details")}
                >
                  <div className="flex items-center">
                    {t("details")}
                    <SortIcon column="details" />
                  </div>
                </TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAndSortedHandles.map((handle, idx) => (
                <TableRow key={`${handle.fd ?? "no-fd"}-${handle.type}-${idx}`}>
                  <TableCell className="font-mono">
                    {handle.fd !== null ? handle.fd : "\u2014"}
                  </TableCell>
                  <TableCell>{handle.type}</TableCell>
                  <TableCell className="font-mono text-xs break-all">
                    {getDetails(handle)}
                  </TableCell>
                </TableRow>
              ))}
              {handles.length === 0 && !isLoading && (
                <TableRow>
                  <TableCell
                    colSpan={3}
                    className="text-center text-muted-foreground"
                  >
                    {t("no_results")}
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        )}
      </div>
    </div>
  );
}

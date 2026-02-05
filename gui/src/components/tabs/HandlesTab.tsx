import { useSession } from "@/context/SessionContext";
import { useMemo, useRef, useState, useEffect } from "react";
import { useTranslation } from "react-i18next";
import { Button } from "@/components/ui/button";
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
import { useRpcQuery } from "@/lib/queries";

import type {
  FileDescriptor,
  VnodeFD,
  SocketFD,
} from "../../../../agent/types/fruity/modules/lsof";

function isVnodeFD(fd: FileDescriptor): fd is VnodeFD {
  return fd.type === "vnode";
}

function isSocketFD(fd: FileDescriptor): fd is SocketFD {
  return fd.type === "socket";
}

function getDetails(handle: FileDescriptor): string {
  if (isVnodeFD(handle)) return handle.path;
  if (isSocketFD(handle))
    return `${handle.protocol} ${handle.lip}:${handle.lport} → ${handle.rip}:${handle.rport}`;
  return "";
}

type SortKey = "fd" | "type" | "details";
type SortOrder = "asc" | "desc";

export function HandlesTab() {
  const { t } = useTranslation();
  const { pid, device } = useSession();
  const [sortKey, setSortKey] = useState<SortKey>("fd");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");
  const [reloadInterval, setReloadInterval] = useState(0);
  const [showVnode, setShowVnode] = useState(true);
  const [showSocket, setShowSocket] = useState(true);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const {
    data: handles = [],
    isLoading,
    refetch,
  } = useRpcQuery<FileDescriptor[]>(["handles"], (api) => api.lsof.fds());

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
        if (handle.type === "vnode" && !showVnode) return false;
        if (handle.type === "socket" && !showSocket) return false;
        return true;
      })
      .sort((a, b) => {
        let cmp = 0;
        switch (sortKey) {
          case "fd":
            cmp = a.fd - b.fd;
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
  }, [handles, sortKey, sortOrder, showVnode, showSocket]);

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
              id="filter-vnode"
              checked={showVnode}
              onCheckedChange={(checked) => setShowVnode(checked === true)}
            />
            <Label htmlFor="filter-vnode" className="text-sm cursor-pointer">
              vnode
            </Label>
          </div>
          <div className="flex items-center gap-2">
            <Checkbox
              id="filter-socket"
              checked={showSocket}
              onCheckedChange={(checked) => setShowSocket(checked === true)}
            />
            <Label htmlFor="filter-socket" className="text-sm cursor-pointer">
              socket
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
              <SelectItem value="1">{t("1s")}</SelectItem>
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
          <div className="flex items-center justify-center h-full text-muted-foreground">
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
              {filteredAndSortedHandles.map((handle) => (
                <TableRow key={handle.fd}>
                  <TableCell className="font-mono">{handle.fd}</TableCell>
                  <TableCell>{handle.type}</TableCell>
                  <TableCell className="font-mono text-xs break-all">
                    {isVnodeFD(handle) && (
                      <a
                        href={`/api/download/${device}/${pid}?path=${encodeURIComponent(
                          handle.path,
                        )}`}
                        className="underline text-amber-600 hover:text-amber-500 dark:text-amber-400 dark:hover:text-amber-300"
                      >
                        {handle.path}
                      </a>
                    )}
                    {isSocketFD(handle) && (
                      <span>
                        {handle.protocol} {handle.lip}:{handle.lport} →{" "}
                        {handle.rip}:{handle.rport}
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {handles.length === 0 && !isLoading && (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-muted-foreground">
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

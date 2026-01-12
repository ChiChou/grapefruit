import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
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
  const { api, status } = useSession();
  const [loading, setLoading] = useState(false);
  const [handles, setHandles] = useState<FileDescriptor[]>([]);
  const [sortKey, setSortKey] = useState<SortKey>("fd");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");
  const [reloadInterval, setReloadInterval] = useState(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const fetchHandles = useCallback(() => {
    if (!api || status !== ConnectionStatus.Ready) return;

    setLoading(true);
    api.lsof
      .fds()
      .then((fds) => setHandles(fds))
      .finally(() => setLoading(false));
  }, [api, status]);

  useEffect(() => fetchHandles(), [fetchHandles]);

  useEffect(() => {
    if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }

    if (reloadInterval > 0 && status === ConnectionStatus.Ready) {
      intervalRef.current = setInterval(fetchHandles, reloadInterval * 1000);
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current);
      }
    };
  }, [reloadInterval, fetchHandles, status]);

  const handleSort = (key: SortKey) => {
    if (sortKey === key) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortKey(key);
      setSortOrder("asc");
    }
  };

  const sortedHandles = useMemo(() => {
    return [...handles].sort((a, b) => {
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
  }, [handles, sortKey, sortOrder]);

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
        <h2 className="text-xl font-semibold">{t("active_file_handles")}</h2>
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
            onClick={fetchHandles}
            disabled={loading || status !== ConnectionStatus.Ready}
          >
            <RefreshCw
              className={`h-4 w-4 mr-2 ${loading ? "animate-spin" : ""}`}
            />
            {t("reload")}
          </Button>
        </div>
      </div>
      <div className="flex-1 overflow-auto border-t border-gray-300 dark:border-gray-700">
        {loading && handles.length === 0 ? (
          <div className="flex items-center justify-center h-full text-gray-500">
            {t("loading")}...
          </div>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead
                  className="w-16 cursor-pointer select-none hover:bg-gray-100 dark:hover:bg-gray-800"
                  onClick={() => handleSort("fd")}
                >
                  <div className="flex items-center">
                    {t("file_descriptor")}
                    <SortIcon column="fd" />
                  </div>
                </TableHead>
                <TableHead
                  className="w-24 cursor-pointer select-none hover:bg-gray-100 dark:hover:bg-gray-800"
                  onClick={() => handleSort("type")}
                >
                  <div className="flex items-center">
                    {t("type")}
                    <SortIcon column="type" />
                  </div>
                </TableHead>
                <TableHead
                  className="cursor-pointer select-none hover:bg-gray-100 dark:hover:bg-gray-800"
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
              {sortedHandles.map((handle) => (
                <TableRow key={handle.fd}>
                  <TableCell className="font-mono">{handle.fd}</TableCell>
                  <TableCell>{handle.type}</TableCell>
                  <TableCell className="font-mono text-xs break-all">
                    {isVnodeFD(handle) && handle.path}
                    {isSocketFD(handle) && (
                      <span>
                        {handle.protocol} {handle.lip}:{handle.lport} →{" "}
                        {handle.rip}:{handle.rport}
                      </span>
                    )}
                  </TableCell>
                </TableRow>
              ))}
              {handles.length === 0 && !loading && (
                <TableRow>
                  <TableCell colSpan={3} className="text-center text-gray-500">
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

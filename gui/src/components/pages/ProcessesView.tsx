import { useState, useMemo } from "react";
import { useParams, Link } from "react-router";
import { useTranslation } from "react-i18next";
import { AlertCircleIcon, ArrowUpDown, Search, XCircle } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface Process {
  name: string;
  pid: number;
  path?: string;
  user?: string;
  ppid?: number;
  started?: string;
}

import type { DeviceInfo } from "@/types/device";

type SortField = "pid" | "name" | "user" | "path";
type SortDirection = "asc" | "desc";

interface SortState {
  field: SortField;
  direction: SortDirection;
}

function DeviceHeader({ deviceInfo: info }: { deviceInfo: DeviceInfo }) {
  const { t } = useTranslation();
  return (
    <>
      <h1 className="mb-2 text-2xl font-bold dark:text-foreground">
        {info.name || t("device")}
      </h1>
      <p className="mb-6 text-sm text-muted-foreground">
        {info.arch} {info.os?.name} {info.os?.version}
        <br />
        {info.udid}
      </p>
    </>
  );
}

function getPlatformFromDeviceInfo(info: DeviceInfo | undefined): "fruity" | "droid" {
  if (info?.os?.name?.toLowerCase().includes("android")) {
    return "droid";
  }
  return "fruity";
}

export function ProcessesView() {
  const { udid } = useParams();
  const { t } = useTranslation();
  const queryClient = useQueryClient();
  const [searchQuery, setSearchQuery] = useState("");
  const [sort, setSort] = useState<SortState>({ field: "pid", direction: "asc" });

  const killProcessMutation = useMutation({
    mutationFn: async (pid: number) => {
      const res = await fetch(`/api/device/${udid}/kill/${pid}`, { method: "POST" });
      if (!res.ok) throw new Error("Failed to kill process");
      return pid;
    },
    onSuccess: (pid) => {
      toast.success(t("process_killed", { pid }));
      queryClient.invalidateQueries({ queryKey: ["processes", udid] });
    },
    onError: () => {
      toast.error(t("failed_to_kill_process"));
    },
  });

  const handleKillProcess = (pid: number, e: React.MouseEvent) => {
    e.preventDefault();
    e.stopPropagation();
    killProcessMutation.mutate(pid);
  };

  const {
    data: processes = [],
    isLoading: processesLoading,
    error: processesError,
  } = useQuery<Process[], Error>({
    queryKey: ["processes", udid],
    queryFn: async ({ signal }) => {
      const res = await fetch(`/api/device/${udid}/processes`, { signal });
      if (!res.ok) throw new Error(t("failed_to_fetch_processes"));
      return res.json();
    },
    enabled: !!udid,
    refetchInterval: 5000,
  });

  const {
    data: deviceInfo,
    isLoading: infoLoading,
    error: infoError,
  } = useQuery<DeviceInfo, Error>({
    queryKey: ["deviceInfo", udid],
    queryFn: async ({ signal }) => {
      const res = await fetch(`/api/device/${udid}/info`, { signal });
      if (!res.ok) throw new Error(t("failed_to_fetch_device_info"));
      return res.json();
    },
    enabled: !!udid,
  });

  const platform = getPlatformFromDeviceInfo(deviceInfo);
  const loading = infoLoading || processesLoading;
  const error = infoError || processesError;

  const handleSort = (field: SortField) => {
    setSort((prev) => ({
      field,
      direction: prev.field === field && prev.direction === "asc" ? "desc" : "asc",
    }));
  };

  const filteredAndSortedProcesses = useMemo(() => {
    const query = searchQuery.toLowerCase();
    const filtered = processes.filter((p) =>
      p.name.toLowerCase().includes(query) ||
      p.pid.toString().includes(query) ||
      p.path?.toLowerCase().includes(query) ||
      p.user?.toLowerCase().includes(query)
    );

    const sortAccessors: Record<SortField, (p: Process) => string | number> = {
      pid: (p) => p.pid,
      name: (p) => p.name.toLowerCase(),
      user: (p) => (p.user ?? "").toLowerCase(),
      path: (p) => (p.path ?? "").toLowerCase(),
    };
    const accessor = sortAccessors[sort.field];
    const dir = sort.direction === "asc" ? 1 : -1;

    return [...filtered].sort((a, b) => {
      const aVal = accessor(a), bVal = accessor(b);
      return aVal < bVal ? -dir : aVal > bVal ? dir : 0;
    });
  }, [processes, searchQuery, sort]);

  const SortableHead = ({ field, children }: { field: SortField; children: React.ReactNode }) => (
    <TableHead
      className="cursor-pointer hover:bg-muted/50 select-none"
      onClick={() => handleSort(field)}
    >
      <div className="flex items-center gap-1">
        {children}
        <ArrowUpDown className={`h-3 w-3 ${sort.field === field ? "text-amber-500" : "text-muted-foreground"}`} />
      </div>
    </TableHead>
  );

  if (loading) {
    return (
      <div className="p-6">
        <Skeleton className="mb-2 h-8 w-48" />
        <Skeleton className="mb-6 h-4 w-96" />

        <div className="mb-6 flex gap-2">
          <Skeleton className="h-9 w-16" />
          <Skeleton className="h-9 w-24" />
        </div>

        <Skeleton className="h-64 w-full" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="p-6 flex items-center justify-center h-full">
        <Alert variant="destructive" className="max-w-md w-full">
          <AlertCircleIcon />
          <AlertTitle>{t("error")}</AlertTitle>
          <AlertDescription>
            <p>{error.message}</p>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="p-6">
      {deviceInfo ? <DeviceHeader deviceInfo={deviceInfo} /> : <></>}

      <div className="mb-4 flex gap-2">
        <Button variant="outline" size="sm" nativeButton={false} render={<Link to={`/list/${udid}/apps`} />}>
          {t("apps")}
        </Button>
        <Button variant="default" size="sm">
          {t("processes")}
        </Button>
      </div>

      <div className="mb-4 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          type="text"
          placeholder={t("search_processes")}
          value={searchQuery}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
          className="pl-10"
        />
      </div>

      {filteredAndSortedProcesses.length === 0 ? (
        <p className="text-center text-muted-foreground">
          {searchQuery ? t("no_processes_matching_search") : t("no_processes_found")}
        </p>
      ) : (
        <div className="rounded-md border">
          <Table>
            <TableHeader>
              <TableRow>
                <SortableHead field="pid">PID</SortableHead>
                <SortableHead field="name">{t("name")}</SortableHead>
                <SortableHead field="user">{t("user")}</SortableHead>
                <SortableHead field="path">{t("path")}</SortableHead>
                <TableHead className="w-12"></TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredAndSortedProcesses.map((process) => (
                <TableRow key={process.pid} className="cursor-pointer">
                  <TableCell>
                    <Link
                      to={`/workspace/${platform}/${udid}/daemon/${process.pid}?name=${encodeURIComponent(process.name)}`}
                      className="text-amber-600 dark:text-amber-400 hover:underline"
                    >
                      {process.pid}
                    </Link>
                  </TableCell>
                  <TableCell>
                    <Link
                      to={`/workspace/${platform}/${udid}/daemon/${process.pid}?name=${encodeURIComponent(process.name)}`}
                      className="block"
                    >
                      {process.name}
                    </Link>
                  </TableCell>
                  <TableCell className="text-muted-foreground">
                    {process.user ?? "-"}
                  </TableCell>
                  <TableCell
                    className="text-muted-foreground text-xs font-mono truncate max-w-xs"
                    title={process.path}
                  >
                    {process.path ?? "-"}
                  </TableCell>
                  <TableCell>
                    <DropdownMenu>
                      <DropdownMenuTrigger
                        render={
                          <button
                            type="button"
                            onClick={(e) => e.stopPropagation()}
                            className="p-1 rounded hover:bg-red-100 dark:hover:bg-red-900/30 text-muted-foreground hover:text-red-500 transition-colors"
                            title={t("kill_process")}
                          />
                        }
                      >
                        <XCircle className="w-4 h-4" />
                      </DropdownMenuTrigger>
                      <DropdownMenuContent align="end">
                        <DropdownMenuItem
                          onClick={(e) => handleKillProcess(process.pid, e)}
                          className="text-destructive focus:text-destructive"
                        >
                          {t("kill_process")}
                        </DropdownMenuItem>
                      </DropdownMenuContent>
                    </DropdownMenu>
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        </div>
      )}
    </div>
  );
}

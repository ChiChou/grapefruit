import { useState, useMemo } from "react";
import { useParams, Link } from "react-router";
import { useTranslation } from "react-i18next";
import { AlertCircleIcon, ArrowUpDown, Search } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

import type { DeviceInfo, Process } from "@shared/schema";

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
      <h1 className="mb-2 text-2xl font-bold dark:text-gray-100">
        {info.name || t("device")}
      </h1>
      <p className="mb-6 text-sm text-gray-600 dark:text-gray-400">
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
  const [searchQuery, setSearchQuery] = useState("");
  const [sort, setSort] = useState<SortState>({ field: "pid", direction: "asc" });

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
    const filtered = processes.filter((process) => {
      const query = searchQuery.toLowerCase();
      return (
        process.name.toLowerCase().includes(query) ||
        process.pid.toString().includes(query) ||
        process.path?.toLowerCase().includes(query) ||
        process.user?.toLowerCase().includes(query)
      );
    });

    const sorted = [...filtered];
    sorted.sort((a, b) => {
      let aValue: string | number = "";
      let bValue: string | number = "";

      switch (sort.field) {
        case "pid":
          aValue = a.pid;
          bValue = b.pid;
          break;
        case "name":
          aValue = a.name.toLowerCase();
          bValue = b.name.toLowerCase();
          break;
        case "user":
          aValue = (a.user ?? "").toLowerCase();
          bValue = (b.user ?? "").toLowerCase();
          break;
        case "path":
          aValue = (a.path ?? "").toLowerCase();
          bValue = (b.path ?? "").toLowerCase();
          break;
      }

      if (aValue < bValue) return sort.direction === "asc" ? -1 : 1;
      if (aValue > bValue) return sort.direction === "asc" ? 1 : -1;
      return 0;
    });
    return sorted;
  }, [processes, searchQuery, sort]);

  const SortHeader = ({ field, children }: { field: SortField; children: React.ReactNode }) => (
    <th
      className="px-4 py-3 text-left font-medium cursor-pointer hover:bg-gray-100 dark:hover:bg-gray-700 select-none"
      onClick={() => handleSort(field)}
    >
      <div className="flex items-center gap-1">
        {children}
        <ArrowUpDown className={`h-3 w-3 ${sort.field === field ? "text-blue-500" : "text-gray-400"}`} />
      </div>
    </th>
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
        <Button variant="outline" size="sm" asChild>
          <Link to={`/list/${udid}/apps`}>{t("apps")}</Link>
        </Button>
        <Button variant="default" size="sm">
          {t("processes")}
        </Button>
      </div>

      <div className="mb-4 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-400" />
        <Input
          type="text"
          placeholder={t("search_processes")}
          value={searchQuery}
          onChange={(e: React.ChangeEvent<HTMLInputElement>) => setSearchQuery(e.target.value)}
          className="pl-10"
        />
      </div>

      {filteredAndSortedProcesses.length === 0 ? (
        <p className="text-center text-gray-500 dark:text-gray-400">
          {searchQuery ? t("no_processes_matching_search") : t("no_processes_found")}
        </p>
      ) : (
        <div className="rounded-md border dark:border-gray-700">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
                <SortHeader field="pid">PID</SortHeader>
                <SortHeader field="name">{t("name")}</SortHeader>
                <SortHeader field="user">{t("user")}</SortHeader>
                <SortHeader field="path">{t("path")}</SortHeader>
              </tr>
            </thead>
            <tbody>
              {filteredAndSortedProcesses.map((process) => (
                <tr
                  key={process.pid}
                  className="border-b last:border-b-0 dark:border-gray-700 hover:bg-amber-50 dark:hover:bg-gray-800 cursor-pointer"
                >
                  <td className="px-4 py-2">
                    <Link
                      to={`/workspace/${platform}/${udid}/daemon/${process.pid}`}
                      className="block text-blue-600 dark:text-blue-400 hover:underline"
                    >
                      {process.pid}
                    </Link>
                  </td>
                  <td className="px-4 py-2 dark:text-gray-100">
                    <Link
                      to={`/workspace/${platform}/${udid}/daemon/${process.pid}`}
                      className="block"
                    >
                      {process.name}
                    </Link>
                  </td>
                  <td className="px-4 py-2 text-gray-600 dark:text-gray-400">
                    {process.user ?? "-"}
                  </td>
                  <td className="px-4 py-2 text-gray-500 dark:text-gray-500 text-xs font-mono truncate max-w-xs" title={process.path}>
                    {process.path ?? "-"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

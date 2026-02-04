import { useState } from "react";
import { useParams, Link } from "react-router";
import { useTranslation } from "react-i18next";
import { AlertCircleIcon, ArrowUpDown, ArrowUp, ArrowDown } from "lucide-react";
import { useQuery } from "@tanstack/react-query";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";

import type { DeviceInfo, Process } from "@shared/schema";

type SortField = "pid" | "name";
type SortOrder = "asc" | "desc";

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
  const [sortField, setSortField] = useState<SortField>("pid");
  const [sortOrder, setSortOrder] = useState<SortOrder>("asc");

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

  const toggleSort = (field: SortField) => {
    if (sortField === field) {
      setSortOrder(sortOrder === "asc" ? "desc" : "asc");
    } else {
      setSortField(field);
      setSortOrder("asc");
    }
  };

  const sortedProcesses = [...processes].sort((a, b) => {
    const modifier = sortOrder === "asc" ? 1 : -1;
    if (sortField === "pid") {
      return (a.pid - b.pid) * modifier;
    }
    return a.name.localeCompare(b.name) * modifier;
  });

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ArrowUpDown className="ml-1 h-4 w-4" />;
    return sortOrder === "asc"
      ? <ArrowUp className="ml-1 h-4 w-4" />
      : <ArrowDown className="ml-1 h-4 w-4" />;
  };

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

      <div className="mb-6 flex gap-2">
        <Button variant="outline" size="sm" asChild>
          <Link to={`/apps/${udid}`}>{t("apps")}</Link>
        </Button>
        <Button variant="default" size="sm">
          {t("processes")}
        </Button>
      </div>

      {processes.length === 0 ? (
        <p className="text-center text-gray-500 dark:text-gray-400">
          {t("no_processes_found")}
        </p>
      ) : (
        <div className="rounded-md border dark:border-gray-700">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b dark:border-gray-700 bg-gray-50 dark:bg-gray-800">
                <th className="px-4 py-3 text-left font-medium">
                  <button
                    className="flex items-center hover:text-gray-900 dark:hover:text-gray-100"
                    onClick={() => toggleSort("pid")}
                  >
                    PID
                    <SortIcon field="pid" />
                  </button>
                </th>
                <th className="px-4 py-3 text-left font-medium">
                  <button
                    className="flex items-center hover:text-gray-900 dark:hover:text-gray-100"
                    onClick={() => toggleSort("name")}
                  >
                    {t("name")}
                    <SortIcon field="name" />
                  </button>
                </th>
              </tr>
            </thead>
            <tbody>
              {sortedProcesses.map((process) => (
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
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

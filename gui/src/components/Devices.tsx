import io from "socket.io-client";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { TriangleAlert, RefreshCw, Plus, X } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

import { Spinner } from "@/components/ui/spinner";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

import { type Device } from "@shared/schema";

export function Devices() {
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [ipAddress, setIpAddress] = useState("");
  const { udid } = useParams();
  const { t } = useTranslation();
  const queryClient = useQueryClient();

  const {
    data: devices = [],
    isLoading: loading,
    error,
    refetch,
  } = useQuery<Device[], Error>({
    queryKey: ["devices"],
    queryFn: async () => {
      const res = await fetch("/api/devices");
      if (!res.ok) {
        throw new Error(t("failed_to_fetch_devices"));
      }
      return res.json();
    },
  });

  const addDeviceMutation = useMutation({
    mutationFn: async (ip: string) => {
      const response = await fetch(`/api/devices/remote/${ip}`, {
        method: "PUT",
      });
      if (response.status !== 204) {
        throw new Error("Failed to add remote device");
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
      setAddMenuOpen(false);
      setIpAddress("");
    },
  });

  const deleteDeviceMutation = useMutation({
    mutationFn: async (ip: string) => {
      await fetch(`/api/devices/remote/${ip}`, {
        method: "DELETE",
      });
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
  });

  const handleAddRemoteDevice = () => {
    if (!ipAddress.trim()) return;
    addDeviceMutation.mutate(ipAddress);
  };

  const handleDeleteRemoteDevice = (ip: string) => {
    deleteDeviceMutation.mutate(ip);
  };

  useEffect(() => {
    const socket = io("/devices").on("change", () => {
      console.log("device changed");
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    });

    return () => {
      socket.disconnect();
    };
  }, [queryClient]);

  if (loading) {
    return (
      <>
        <h2 className="mb-4 text-lg  dark:text-gray-100 font-light">
          <Spinner className="inline-block h-5 w-5 animate-spin" />
        </h2>
        <div className="flex flex-col gap-2" role="status" aria-live="polite">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-8 w-3/4 rounded-md bg-gray-200 dark:bg-gray-700 animate-pulse"
            />
          ))}
        </div>
      </>
    );
  }

  if (error) {
    return (
      <>
        <p className="text-sm text-red-500 dark:text-red-400">
          {t("error")}: {error.message}
        </p>
      </>
    );
  }

  return (
    <>
      <div className="flex items-end justify-between mb-4">
        <Button
          variant="outline"
          size="icon-sm"
          onClick={() => refetch()}
          title={t("reload")}
        >
          <RefreshCw className="h-4 w-4" />
        </Button>
        <DropdownMenu open={addMenuOpen} onOpenChange={setAddMenuOpen}>
          <DropdownMenuTrigger asChild>
            <Button variant="outline" size="icon-sm" title={t("add_device")}>
              <Plus className="h-4 w-4" />
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="start" className="w-64 p-4">
            <div className="space-y-3">
              <label className="text-sm font-medium">
                {t("add_remote_device")}
              </label>
              <input
                type="text"
                placeholder={t("ip_address")}
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                onKeyDown={(e) => {
                  if (e.key === "Enter") handleAddRemoteDevice();
                }}
                className="w-full rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
              />
              <div className="flex gap-2">
                <Button
                  size="sm"
                  onClick={handleAddRemoteDevice}
                  disabled={addDeviceMutation.isPending || !ipAddress.trim()}
                >
                  {t("confirm")}
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setAddMenuOpen(false);
                    setIpAddress("");
                  }}
                >
                  {t("cancel")}
                </Button>
              </div>
            </div>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
      <Separator className="mb-4" />
      {devices.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400 text-center flex items-center justify-center gap-2">
          <TriangleAlert className="h-4 w-4" />
          {t("no_devices_found")}
        </p>
      ) : (
        <ul className="flex flex-col gap-2">
          {devices.map((device) => (
            <li key={device.id} className="flex items-center gap-2">
              <Link
                to={`/apps/${device.id}`}
                className={`flex-1 block rounded-md px-3 py-2 text-sm transition-colors hover:bg-gray-200 dark:hover:bg-gray-700 ${
                  udid === device.id
                    ? "bg-gray-300 font-medium dark:bg-gray-700 dark:text-gray-100"
                    : "text-gray-700 dark:text-gray-300"
                }`}
              >
                {device.name || device.id}
              </Link>
              {device.type === "remote" && (
                <Button
                  variant="ghost"
                  size="icon-sm"
                  onClick={() => handleDeleteRemoteDevice(device.id)}
                  title={t("delete")}
                  className="shrink-0"
                >
                  <X className="h-4 w-4" />
                </Button>
              )}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

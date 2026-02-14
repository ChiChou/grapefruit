import io from "socket.io-client";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { TriangleAlert, RefreshCw, Plus, X } from "lucide-react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { toast } from "sonner";

import { Spinner } from "@/components/ui/spinner";
import { Separator } from "@/components/ui/separator";
import { Button } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

interface Device {
  id: string;
  type: "usb" | "local" | "remote";
  removable: boolean;
  name: string;
}

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
    onError: (error) => {
      toast.error(error.message);
    },
  });

  const deleteDeviceMutation = useMutation({
    mutationFn: async (ip: string) => {
      const response = await fetch(`/api/devices/remote/${ip}`, {
        method: "DELETE",
      });
      if (!response.ok) {
        throw new Error("Failed to remove remote device");
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["devices"] });
    },
    onError: (error) => {
      toast.error(error.message);
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
        <h2 className="mb-4 text-lg  dark:text-foreground font-light">
          <Spinner className="inline-block h-5 w-5 animate-spin" />
        </h2>
        <div className="flex flex-col gap-2" role="status" aria-live="polite">
          {Array.from({ length: 3 }).map((_, i) => (
            <div
              key={i}
              className="h-8 w-3/4 rounded-md bg-accent animate-pulse"
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
                className="w-full rounded-md border border-input bg-background px-3 py-2 text-sm"
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
        <p className="text-sm text-muted-foreground text-center flex items-center justify-center gap-2">
          <TriangleAlert className="h-4 w-4" />
          {t("no_devices_found")}
        </p>
      ) : (
        <ul className="flex flex-col gap-2">
          {devices.map((device) => (
            <li key={device.id} className="flex items-center gap-2 min-w-0">
              <Link
                to={`/list/${device.id}/apps`}
                className={`flex-1 block rounded-md px-3 py-2 text-sm transition-colors hover:bg-accent min-w-0 truncate ${
                  udid === device.id
                    ? "bg-accent font-medium text-accent-foreground"
                    : "text-muted-foreground"
                }`}
                title={device.name || device.id}
              >
                {device.name || device.id}
              </Link>
              {device.type === "remote" && (
                <DropdownMenu>
                  <DropdownMenuTrigger asChild>
                    <Button
                      variant="ghost"
                      size="icon-sm"
                      title={t("delete")}
                      className="shrink-0 flex-none"
                    >
                      <X className="h-4 w-4" />
                    </Button>
                  </DropdownMenuTrigger>
                  <DropdownMenuContent align="end">
                    <DropdownMenuItem
                      onClick={() => handleDeleteRemoteDevice(device.id)}
                      className="text-destructive focus:text-destructive"
                    >
                      {t("disconnect")}
                    </DropdownMenuItem>
                  </DropdownMenuContent>
                </DropdownMenu>
              )}
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

import io from "socket.io-client";
import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { useTranslation } from "react-i18next";
import { TriangleAlert, RefreshCw, Plus, X } from "lucide-react";

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
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [addMenuOpen, setAddMenuOpen] = useState(false);
  const [ipAddress, setIpAddress] = useState("");
  const [isAdding, setIsAdding] = useState(false);
  const { udid } = useParams();
  const { t } = useTranslation();

  const loadDevices = () => {
    console.log("load devices");
    fetch("/api/devices")
      .then((res) => {
        if (!res.ok) {
          throw new Error(t("failed_to_fetch_devices"));
        }
        return res.json();
      })
      .then((data) => {
        setDevices(data);
        setLoading(false);
      })
      .catch((err) => {
        setError(err.message);
        setLoading(false);
      });
  };

  const handleAddRemoteDevice = async () => {
    if (!ipAddress.trim()) return;

    setIsAdding(true);
    try {
      const response = await fetch(`/api/devices/remote/${ipAddress}`, {
        method: "PUT",
      });

      if (response.status === 204) {
        setAddMenuOpen(false);
        setIpAddress("");
        loadDevices();
      }
    } catch (err) {
      console.error("Failed to add remote device:", err);
    } finally {
      setIsAdding(false);
    }
  };

  const handleDeleteRemoteDevice = async (ip: string) => {
    try {
      await fetch(`/api/devices/remote/${ip}`, {
        method: "DELETE",
      });
      loadDevices();
    } catch (err) {
      console.error("Failed to delete remote device:", err);
    }
  };

  useEffect(() => {
    const socket = io("/devices").on("change", () => {
      console.log("device changed");
      loadDevices();
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  useEffect(loadDevices, []);

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
          {t("error")}: {error}
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
          onClick={loadDevices}
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
                  disabled={isAdding || !ipAddress.trim()}
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
        <ul className="flex gap-0 sm:flex-col sm:space-y-2">
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

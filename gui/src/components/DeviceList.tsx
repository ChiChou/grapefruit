import { useEffect, useState } from "react";
import { Link, useParams } from "react-router";
import { useTranslation } from "react-i18next";
import io from "socket.io-client";

import { Spinner } from "@/components/ui/spinner";
import { Separator } from "@/components/ui/separator";

interface Device {
  id: string;
  type: "usb" | "tether" | "remote";
  removable: boolean;
  name: string;
}

export function DeviceList() {
  const [devices, setDevices] = useState<Device[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { udid } = useParams();
  const { t } = useTranslation();

  const loadDevices = () => {
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

  useEffect(() => {
    const socket = io("/devices").on("change", () => {
      loadDevices();
    });

    return () => {
      socket.disconnect();
    };
  }, []);

  useEffect(loadDevices);

  if (loading) {
    return (
      <>
        <h2 className="mb-4 text-lg  dark:text-gray-100 font-light">
          {t("devices")}{" "}
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
        <h2 className="mb-4 text-lg  dark:text-gray-100 font-light">
          {t("devices")}
        </h2>
        <p className="text-sm text-red-500 dark:text-red-400">
          {t("error")}: {error}
        </p>
      </>
    );
  }

  return (
    <>
      <Separator className="mb-4" />
      <h2 className="mb-4 text-lg  dark:text-gray-100 font-light">
        {t("devices")}
      </h2>
      {devices.length === 0 ? (
        <p className="text-sm text-gray-500 dark:text-gray-400">
          {t("no_devices_found")}
        </p>
      ) : (
        <ul className="flex gap-0 sm:flex-col sm:space-y-2">
          {devices.map((device) => (
            <li key={device.id}>
              <Link
                to={`/apps/${device.id}`}
                className={`block rounded-md px-3 py-2 text-sm transition-colors hover:bg-gray-200 dark:hover:bg-gray-700 ${
                  udid === device.id
                    ? "bg-gray-300 font-medium dark:bg-gray-700 dark:text-gray-100"
                    : "text-gray-700 dark:text-gray-300"
                }`}
              >
                {device.name || device.id}
              </Link>
            </li>
          ))}
        </ul>
      )}
    </>
  );
}

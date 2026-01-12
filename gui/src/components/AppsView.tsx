import { useParams, Link } from "react-router";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { AlertCircleIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

import type { Application, DeviceInfo } from "@shared/schema";

function AppCardSkeleton() {
  return (
    <div className="block rounded-lg py-6 px-2">
      <div className="mb-3 flex items-center justify-center">
        <Skeleton className="h-16 w-16 rounded-xl" />
      </div>
      <div className="space-y-1 text-center">
        <Skeleton className="mx-auto h-4 w-20" />
        <Skeleton className="mx-auto h-3 w-24" />
      </div>
    </div>
  );
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

interface AppCardProps {
  app: Application;
  udid: string;
}

function AppCard({ app, udid }: AppCardProps) {
  return (
    <Link
      to={`/workspace/${udid}/${app.identifier}`}
      className="block rounded-lg py-6 px-2 transition-colors  hover:bg-amber-100 dark:hover:bg-gray-800"
    >
      <div className="relative mb-3 flex items-center justify-center">
        <img
          src={`/api/device/${udid}/icon/${app.identifier}`}
          alt={app.name}
          loading="lazy"
          className="h-16 w-16 rounded-xl"
          onError={(e) => {
            e.currentTarget.src =
              "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64'%3E%3Crect width='64' height='64' fill='%23ddd'/%3E%3C/svg%3E";
          }}
        />
        {app.pid !== 0 && (
          <Badge
            className="absolute -right-1 -top-1 bg-green-500 px-1.5 py-0.5 text-xs"
            variant="default"
          >
            {app.pid}
          </Badge>
        )}
      </div>
      <div className="space-y-1 text-center">
        <p className="line-clamp-2 text-sm font-medium leading-tight dark:text-gray-100">
          {app.name}
        </p>
        <p className="line-clamp-1 text-xs text-gray-500 dark:text-gray-400">
          {app.identifier}
        </p>
      </div>
    </Link>
  );
}

export function AppsView() {
  const { udid } = useParams();
  const [apps, setApps] = useState<Application[]>([]);
  const [deviceInfo, setDeviceInfo] = useState<DeviceInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const { t } = useTranslation();

  useEffect(() => {
    if (!udid) return;

    setLoading(true);
    setError(null);

    const abortController = new AbortController();

    Promise.all([
      fetch(`/api/device/${udid}/apps`, {
        signal: abortController.signal,
      }).then((res) => {
        if (!res.ok) throw new Error(t("failed_to_fetch_apps"));
        return res.json();
      }),
      fetch(`/api/device/${udid}/info`, {
        signal: abortController.signal,
      }).then((res) => {
        if (!res.ok) throw new Error(t("failed_to_fetch_device_info"));
        return res.json();
      }),
    ])
      .then(([appsData, infoData]) => {
        setApps(appsData);
        setDeviceInfo(infoData);
      })
      .catch((err) => {
        if (err.name === "AbortError") {
          // Request was cancelled, don't update state
          return;
        }
        setError(err.message);
      })
      .finally(() => {
        setLoading(false);
      });

    return () => {
      abortController.abort();
    };
  }, [udid, t]);

  if (loading) {
    return (
      <div className="p-6">
        <Skeleton className="mb-2 h-8 w-48" />
        <Skeleton className="mb-6 h-4 w-96" />

        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
          {Array.from({ length: 12 }).map((_, i) => (
            <AppCardSkeleton key={i} />
          ))}
        </div>
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
            <p>{error}</p>
          </AlertDescription>
        </Alert>
      </div>
    );
  }

  return (
    <div className="p-6">
      {deviceInfo ? <DeviceHeader deviceInfo={deviceInfo} /> : <></>}

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-6">
        {apps.map((app) => (
          <AppCard key={app.identifier} app={app} udid={udid!} />
        ))}
      </div>

      {apps.length === 0 && (
        <p className="text-center text-gray-500 dark:text-gray-400">
          {t("no_apps_found")}
        </p>
      )}
    </div>
  );
}

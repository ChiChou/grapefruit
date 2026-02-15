import { useParams, Link, useSearchParams } from "react-router";
import { useTranslation } from "react-i18next";
import { AlertCircleIcon, Search } from "lucide-react";
import { useQuery } from "@tanstack/react-query";
import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface Application {
  name: string;
  identifier: string;
  pid: number;
}

import type { DeviceInfo } from "@/types/device";

function AppCardSkeleton() {
  return (
    <div className="block rounded-lg p-6 max-w-40 mx-auto">
      <div className="mb-3 flex items-center justify-center">
        <Skeleton className="h-16 w-16 rounded-2xl" />
      </div>
      <div className="space-y-1 text-center">
        <Skeleton className="mx-auto h-5 w-24" />
        <Skeleton className="mx-auto h-3 w-28" />
      </div>
    </div>
  );
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

function getPlatformFromDeviceInfo(
  info: DeviceInfo | undefined,
): "fruity" | "droid" {
  if (info?.os?.name?.toLowerCase().includes("android")) {
    return "droid";
  }
  return "fruity";
}

interface AppCardProps {
  app: Application;
  udid: string;
  platform: "fruity" | "droid";
}

function AppCard({ app, udid, platform }: AppCardProps) {
  return (
    <Link
      to={`/workspace/${platform}/${udid}/app/${app.identifier}`}
      className="block rounded-lg p-6 transition-colors hover:bg-accent dark:hover:bg-accent max-w-40 mx-auto"
    >
      <div className="relative mb-3 flex items-center justify-center">
        <img
          src={`/api/device/${udid}/icon/${app.identifier}`}
          alt={app.name}
          loading="lazy"
          className="h-16 w-16 rounded-2xl"
          onError={(e) => {
            e.currentTarget.src =
              "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='48' height='48'%3E%3Crect width='48' height='48' fill='%23ddd'/%3E%3C/svg%3E";
          }}
        />
        {app.pid !== 0 && (
          <Badge
            className="absolute -right-1 -top-1 bg-green-500 px-1 py-0 text-[10px]"
            variant="default"
          >
            {app.pid}
          </Badge>
        )}
      </div>
      <div className="space-y-1 text-center">
        <p className="line-clamp-2 text-sm font-medium leading-tight dark:text-foreground">
          {app.name}
        </p>
        <p className="line-clamp-1 text-xs text-muted-foreground">
          {app.identifier}
        </p>
      </div>
    </Link>
  );
}

export function AppsView() {
  const { udid } = useParams();
  const { t } = useTranslation();
  const [searchParams] = useSearchParams();
  const platformParam = searchParams.get("platform");
  const [searchQuery, setSearchQuery] = useState("");

  const {
    data: apps = [],
    isLoading: appsLoading,
    error: appsError,
  } = useQuery<Application[], Error>({
    queryKey: ["apps", udid, platformParam],
    queryFn: async ({ signal }) => {
      const url = platformParam
        ? `/api/device/${udid}/apps?platform=${platformParam}`
        : `/api/device/${udid}/apps`;
      const res = await fetch(url, { signal });
      if (!res.ok) throw new Error(t("failed_to_fetch_apps"));
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

  const platform =
    (platformParam as "fruity" | "droid" | null) ||
    getPlatformFromDeviceInfo(deviceInfo);
  const loading = infoLoading || appsLoading;
  const error = infoError || appsError;

  const filteredApps = apps.filter((app) => {
    const query = searchQuery.toLowerCase();
    return (
      app.name.toLowerCase().includes(query) ||
      app.identifier.toLowerCase().includes(query)
    );
  });

  if (loading) {
    return (
      <div className="p-6">
        <Skeleton className="mb-2 h-8 w-48" />
        <Skeleton className="mb-6 h-4 w-96" />

        <div className="mb-6 flex gap-2">
          <Skeleton className="h-9 w-16" />
          <Skeleton className="h-9 w-24" />
        </div>

        <div className="grid grid-cols-2 gap-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 2xl:grid-cols-10">
          {Array.from({ length: 16 }).map((_, i) => (
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
        <Button variant="default" size="sm">
          {t("apps")}
        </Button>
        <Button variant="outline" size="sm" nativeButton={false} render={<Link to={`/list/${udid}/processes`} />}>
          {t("processes")}
        </Button>
      </div>

      <div className="mb-4 relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          type="text"
          placeholder={t("search_apps")}
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="pl-10"
        />
      </div>

      <div className="grid grid-cols-2 gap-6 sm:grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-6 2xl:grid-cols-8 3xl:grid-cols-10">
        {filteredApps.map((app) => (
          <AppCard
            key={app.identifier}
            app={app}
            udid={udid!}
            platform={platform}
          />
        ))}
      </div>

      {filteredApps.length === 0 && (
        <p className="text-center text-muted-foreground py-8">
          {searchQuery ? t("no_apps_matching_search") : t("no_apps_found")}
        </p>
      )}
    </div>
  );
}

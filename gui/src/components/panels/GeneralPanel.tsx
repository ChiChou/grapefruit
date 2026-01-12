import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type {
  BasicInfo,
  URLScheme,
} from "../../../../agent/src/fruity/modules/info";
import { useParams } from "react-router";

export function GeneralPanel() {
  const { device, bundle } = useParams();
  const { t } = useTranslation();
  const { api, status } = useSession();
  const [basicInfo, setBasicInfo] = useState<BasicInfo | null>(null);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!api || status !== ConnectionStatus.Ready) return;

    setIsLoading(true);
    setError(null);
    api.info
      .basics()
      .then((info) => setBasicInfo(info))
      .catch((error) => {
        setError(error?.message);
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, [status, api]);

  return (
    <div className="h-full p-4 overflow-auto">
      <h2 className="text-xl font-semibold mb-4">{t("general")}</h2>
      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertTitle>{t("error")}</AlertTitle>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {isLoading ? (
        <div className="space-y-4">
          <div className="flex gap-4">
            <Skeleton className="h-16 w-16 rounded-xl shrink-0" />
            <div className="flex-1 space-y-2">
              <Skeleton className="h-4 w-24" />
              <Skeleton className="h-4 w-full" />
            </div>
          </div>
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-3/4" />
        </div>
      ) : basicInfo ? (
        <div className="space-y-4">
          <div className="flex gap-4">
            <img
              src={`/api/device/${device}/icon/${bundle}`}
              alt={basicInfo.label}
              loading="lazy"
              className="h-16 w-16 rounded-xl shrink-0"
              onError={(e) => {
                e.currentTarget.src =
                  "data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='64' height='64'%3E%3Crect width='64' height='64' fill='%23ddd'/%3E%3C/svg%3E";
              }}
            />
            <div className="flex-1 min-w-0">
              <div>
                <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                  {t("app_name")}
                </div>
                <div className="text-sm">{basicInfo.label || t("na")}</div>
              </div>
              <div className="mt-2">
                <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
                  {t("bundle_id")}
                </div>
                <div className="text-sm font-mono break-all">
                  {basicInfo.id || t("na")}
                </div>
              </div>
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("version")}
            </div>
            <div className="flex items-center gap-2 text-sm">
              <span>{basicInfo.version || t("na")}</span>
              <Badge variant="secondary" className="text-xs">
                {basicInfo.semVer || t("na")}
              </Badge>
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("min_os")}
            </div>
            <Badge variant="outline">{basicInfo.minOS || t("na")}</Badge>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("bundle_path")}
            </div>
            <div className="text-sm font-mono break-all">
              {basicInfo.path || t("na")}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("executable")}
            </div>
            <div className="text-sm font-mono break-all">
              {basicInfo.main || t("na")}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("tmp_dir")}
            </div>
            <div className="text-sm font-mono break-all">
              {basicInfo.tmp || t("na")}
            </div>
          </div>
          <div>
            <div className="text-xs text-gray-500 dark:text-gray-400 mb-1">
              {t("home_dir")}
            </div>
            <div className="text-sm font-mono break-all">
              {basicInfo.home || t("na")}
            </div>
          </div>
          {basicInfo.urls && basicInfo.urls.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 dark:text-gray-400 mb-2">
                {t("url_schemes")}
              </div>
              <div className="space-y-2">
                {basicInfo.urls.map((urlScheme: URLScheme, index: number) => (
                  <div key={index} className="text-sm">
                    <Badge variant="outline" className="mb-1">
                      {urlScheme.name}
                    </Badge>
                    <div className="text-xs text-gray-500 dark:text-gray-400 break-all">
                      {urlScheme.schemes.join(", ")}
                      <span className="ml-1">({urlScheme.role})</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : status === ConnectionStatus.Ready ? (
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {t("no_app_info")}
        </div>
      ) : (
        <div className="text-sm text-gray-500 dark:text-gray-400">
          {t("connect_to_view_app_info")}
        </div>
      )}
    </div>
  );
}

import { ConnectionStatus, useSession } from "@/context/SessionContext";
import { useEffect, useState } from "react";
import { useTranslation } from "react-i18next";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import type {
  BasicInfo,
  URLScheme,
} from "../../../../agent/src/fruity/modules/info";

export function GeneralPanel() {
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
        setError(error?.message || t("failed_to_fetch_app_info"));
      })
      .finally(() => {
        setIsLoading(false);
      });
  }, [status, api, t]);

  return (
    <div className="h-full p-4">
      <h2 className="text-xl font-semibold mb-4">{t("general")}</h2>
      <div className="space-y-4">
        {error && (
          <Alert variant="destructive">
            <AlertTitle>{t("error")}</AlertTitle>
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}
        <Card>
          <CardContent>
            {isLoading ? (
              <div className="space-y-3">
                <Skeleton className="h-4 w-32" />
                <Skeleton className="h-4 w-48" />
                <Skeleton className="h-4 w-40" />
                <Skeleton className="h-4 w-36" />
              </div>
            ) : basicInfo ? (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{t("label")}</span>
                  <span className="text-sm">{basicInfo.label || t("na")}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{t("bundle_id")}</span>
                  <span className="text-sm font-mono">
                    {basicInfo.id || t("na")}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{t("version")}</span>
                  <div className="flex items-center gap-2">
                    <span className="text-sm">
                      {basicInfo.version || t("na")}
                    </span>
                    <Badge variant="secondary" className="text-xs">
                      {basicInfo.semVer || t("na")}
                    </Badge>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{t("min_os")}</span>
                  <Badge variant="outline">{basicInfo.minOS || t("na")}</Badge>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">
                    {t("bundle_path")}
                  </span>
                  <span className="text-sm font-mono max-w-xs truncate">
                    {basicInfo.path || t("na")}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{t("executable")}</span>
                  <span className="text-sm font-mono max-w-xs truncate">
                    {basicInfo.main || t("na")}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{t("tmp_dir")}</span>
                  <span className="text-sm font-mono max-w-xs truncate">
                    {basicInfo.tmp || t("na")}
                  </span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm font-medium">{t("home_dir")}</span>
                  <span className="text-sm font-mono max-w-xs truncate">
                    {basicInfo.home || t("na")}
                  </span>
                </div>
                {basicInfo.urls && basicInfo.urls.length > 0 && (
                  <div className="space-y-2">
                    <span className="text-sm font-medium">
                      {t("url_schemes")}:
                    </span>
                    <div className="space-y-1">
                      {basicInfo.urls.map(
                        (urlScheme: URLScheme, index: number) => (
                          <div
                            key={index}
                            className="flex items-center gap-2 text-xs"
                          >
                            <Badge variant="outline">{urlScheme.name}</Badge>
                            <span className="text-gray-500">
                              {urlScheme.schemes.join(", ")}
                            </span>
                            <span className="text-gray-400">
                              ({urlScheme.role})
                            </span>
                          </div>
                        ),
                      )}
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
          </CardContent>
        </Card>
      </div>
    </div>
  );
}

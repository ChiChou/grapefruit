import { useState } from "react";
import { useTranslation } from "react-i18next";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { InfoPlistInsights } from "@/components/tabs/InfoPlistInsights";
import { useRpcQuery } from "@/lib/queries";

export function FruityInfoPlistInsightsTab() {
  const { t } = useTranslation();
  const [permsOpen, setPermsOpen] = useState(false);

  const {
    data,
    isLoading,
    error,
  } = useRpcQuery(["infoPlist"], (api) => api.info.plist());

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const value = (data?.value as Record<string, any>) ?? null;

  return (
    <div className="h-full flex flex-col">
      <div className="flex-1 overflow-hidden">
        {error ? (
          <div className="p-4">
            <Alert variant="destructive">
              <AlertTitle>{t("error")}</AlertTitle>
              <AlertDescription>{(error as Error)?.message}</AlertDescription>
            </Alert>
          </div>
        ) : isLoading ? (
          <div className="p-4 space-y-4">
            <Skeleton className="h-8 w-48" />
            <Skeleton className="h-4 w-full" />
            <Skeleton className="h-4 w-3/4" />
            <Skeleton className="h-4 w-1/2" />
          </div>
        ) : value ? (
          <InfoPlistInsights value={value} permsOpen={permsOpen} setPermsOpen={setPermsOpen} />
        ) : (
          <div className="flex items-center justify-center h-full text-muted-foreground">
            {t("no_content")}
          </div>
        )}
      </div>
    </div>
  );
}

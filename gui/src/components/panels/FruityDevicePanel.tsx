import { useTranslation } from "react-i18next";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

import { useRpcQuery } from "@/lib/queries";

import type { UIDeviceInfo } from "@agent/fruity/modules/uidevice";

export function FruityDevicePanel() {
  const { t } = useTranslation();

  const {
    data: deviceInfo,
    isLoading,
    error,
  } = useRpcQuery<UIDeviceInfo>(["uideviceInfo"], (api) => api.uidevice.info());

  return (
    <div className="h-full p-4 overflow-auto">
      {error && (
        <Alert variant="destructive" className="mb-4">
          <AlertTitle>{t("error")}</AlertTitle>
          <AlertDescription>{(error as Error)?.message}</AlertDescription>
        </Alert>
      )}
      {isLoading ? (
        <div className="space-y-4">
          <Skeleton className="h-4 w-24" />
          <Skeleton className="h-4 w-3/4" />
          <Skeleton className="h-4 w-1/2" />
        </div>
      ) : deviceInfo ? (
        <div className="space-y-4 pb-4">
          <div className="text-sm font-medium">{t("device_info")}</div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <div className="text-sm text-muted-foreground mb-1">
                {t("uidevice_name")}
              </div>
              <div className="text-sm">{deviceInfo.name}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">
                {t("model")}
              </div>
              <div className="text-sm">{deviceInfo.model}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">
                {t("uidevice_localized_model")}
              </div>
              <div className="text-sm">{deviceInfo.localizedModel}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">
                {t("uidevice_system")}
              </div>
              <div className="text-sm">{deviceInfo.systemName} {deviceInfo.systemVersion}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">
                {t("uidevice_idiom")}
              </div>
              <div className="text-sm">{deviceInfo.userInterfaceIdiom}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">
                {t("uidevice_battery")}
              </div>
              <div className="text-sm">
                {deviceInfo.batteryLevel >= 0
                  ? `${Math.round(deviceInfo.batteryLevel * 100)}%`
                  : "N/A"}{" "}
                ({deviceInfo.batteryState})
              </div>
            </div>
            <div className="col-span-2">
              <div className="text-sm text-muted-foreground mb-1">
                {t("uidevice_idfv")}
              </div>
              <div className="text-sm font-mono">{deviceInfo.identifierForVendor}</div>
            </div>
            <div>
              <div className="text-sm text-muted-foreground mb-1">
                {t("uidevice_multitasking")}
              </div>
              <div className="text-sm">{deviceInfo.isMultitaskingSupported ? "Yes" : "No"}</div>
            </div>
          </div>
        </div>
      ) : (
        <div className="text-sm text-muted-foreground">
          {t("no_device_info")}
        </div>
      )}
    </div>
  );
}

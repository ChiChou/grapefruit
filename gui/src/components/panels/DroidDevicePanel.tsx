import { useTranslation } from "react-i18next";

import { Skeleton } from "@/components/ui/skeleton";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";

import { useDroidRpcQuery } from "@/lib/queries";

import type { DeviceInfo } from "@agent/droid/modules/device";

export function DroidDevicePanel() {
  const { t } = useTranslation();

  const {
    data: deviceInfo,
    isLoading,
    error,
  } = useDroidRpcQuery<DeviceInfo>(["deviceInfo"], (api) => api.device.info());

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
              <div className="text-xs text-muted-foreground mb-1">
                {t("model")}
              </div>
              <div className="text-sm">{deviceInfo.model}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">
                {t("brand")}
              </div>
              <div className="text-sm">{deviceInfo.brand}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">
                {t("manufacturer")}
              </div>
              <div className="text-sm">{deviceInfo.manufacturer}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">
                {t("android_version")}
              </div>
              <div className="text-sm">{deviceInfo.release}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">
                {t("sdk_version")}
              </div>
              <div className="text-sm">{deviceInfo.sdk}</div>
            </div>
            <div>
              <div className="text-xs text-muted-foreground mb-1">
                ABI
              </div>
              <div className="text-sm font-mono">{deviceInfo.abi}</div>
            </div>
            <div className="col-span-2">
              <div className="text-xs text-muted-foreground mb-1">
                {t("security_patch")}
              </div>
              <div className="text-sm">{deviceInfo.security}</div>
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

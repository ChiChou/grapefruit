import { useTranslation } from "react-i18next";

import { PlistView, type PlistValue } from "@/components/shared/UnifiedPlistViewer";
import { useRpcQuery } from "@/lib/queries";

export function FruityInfoPlistTab() {
  const { t } = useTranslation();

  const { data, isLoading } = useRpcQuery(["infoPlist"], (api) =>
    api.info.plist()
  );

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-full text-muted-foreground">
        {t("loading")}
      </div>
    );
  }

  return (
    <PlistView
      xml={data?.xml ?? ""}
      value={(data?.value as PlistValue) ?? null}
      filename="Info.plist"
    />
  );
}

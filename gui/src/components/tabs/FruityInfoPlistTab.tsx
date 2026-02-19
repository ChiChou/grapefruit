import { useTranslation } from "react-i18next";
import { Loader2 } from "lucide-react";

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
        <Loader2 className="h-4 w-4 animate-spin mr-2" />
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

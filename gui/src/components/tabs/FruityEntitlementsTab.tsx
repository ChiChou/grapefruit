import { useTranslation } from "react-i18next";
import type { IDockviewPanelProps } from "dockview";

import { PlistView, type PlistValue } from "@/components/shared/UnifiedPlistViewer";
import { useRpcQuery } from "@/lib/queries";

export interface EntitlementsTabParams {
  path?: string;
}

export function FruityEntitlementsTab({
  params,
}: IDockviewPanelProps<EntitlementsTabParams>) {
  const { t } = useTranslation();

  const { data, isLoading } = useRpcQuery(
    ["entitlements", params?.path ?? ""],
    (api) => api.entitlements.plist(params?.path)
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
      filename="Entitlements.plist"
    />
  );
}

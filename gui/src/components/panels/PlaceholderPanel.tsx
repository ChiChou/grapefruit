import { useTranslation } from "react-i18next";
import { Construction } from "lucide-react";

import { useSession, Platform, Mode } from "@/context/SessionContext";

export function PlaceholderPanel() {
  const { t } = useTranslation();
  const { platform, mode } = useSession();

  const getPlatformName = () => {
    if (platform === Platform.Fruity) return "iOS";
    if (platform === Platform.Droid) return "Android";
    return "Unknown";
  };

  const getModeName = () => {
    if (mode === Mode.App) return t("app");
    if (mode === Mode.Daemon) return t("daemon");
    return "Unknown";
  };

  return (
    <div className="flex flex-col items-center justify-center h-full text-muted-foreground gap-4">
      <Construction className="h-16 w-16" />
      <div className="text-center">
        <h2 className="text-lg font-semibold mb-2">
          {getPlatformName()} {getModeName()} {t("mode")}
        </h2>
        <p className="text-sm">
          {t("feature_coming_soon")}
        </p>
      </div>
    </div>
  );
}

import { useTranslation } from "react-i18next";

import logo from "@/assets/logo.svg";
import { useDock } from "@/context/DockContext";
import { useSession } from "@/context/SessionContext";
import { getPanelFeatures, type PanelFeature } from "@/lib/features";

function LauncherItem({ feature }: { feature: PanelFeature }) {
  const { t } = useTranslation();
  const { openSingletonPanel } = useDock();

  const title = t(feature.label);
  const Icon = feature.icon;

  return (
    <button
      type="button"
      onClick={() =>
        openSingletonPanel({
          id: feature.id,
          component: feature.component,
          title,
          params: feature.params,
        })
      }
      className="w-56 flex items-center gap-3 p-3 rounded-lg hover:bg-accent transition-colors"
      title={t(feature.desc)}
    >
      <div className="w-14 h-14 shrink-0 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
        <Icon className="w-8 h-8" />
      </div>
      <span className="text-base font-medium truncate">
        {title}
      </span>
    </button>
  );
}

export function HomeTab() {
  const { platform, mode } = useSession();
  const features = getPanelFeatures(platform, mode);

  return (
    <div className="h-full flex flex-col p-4 overflow-auto">
      <div className="flex flex-wrap content-start gap-1 flex-1">
        {features.map((feature) => (
          <LauncherItem key={feature.id} feature={feature} />
        ))}
      </div>
      <div className="flex justify-end mt-4">
        <img src={logo} alt="logo" className="h-6 w-24" />
      </div>
    </div>
  );
}

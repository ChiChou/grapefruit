import { useTranslation } from "react-i18next";

import logo from "@/assets/logo.svg";
import { useDock } from "@/context/DockContext";
import { useSession } from "@/context/SessionContext";
import { getPanelFeatures, type PanelFeature } from "@/lib/features";

function LauncherItem({ feature }: { feature: PanelFeature }) {
  const { t } = useTranslation();
  const { openSingletonPanel } = useDock();

  const title = feature.labelKey ? t(feature.labelKey) : feature.labelFallback;
  const desc = feature.descKey ? t(feature.descKey) : feature.descFallback;
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
      className="flex items-center gap-3 p-3 rounded-lg hover:bg-accent transition-colors text-left"
    >
      <div className="w-12 h-12 shrink-0 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
        <Icon className="w-6 h-6" />
      </div>
      <div className="min-w-0">
        <h3 className="font-medium text-base">{title}</h3>
        <p className="text-sm text-muted-foreground truncate">{desc}</p>
      </div>
    </button>
  );
}

export function HomeTab() {
  const { platform, mode } = useSession();
  const features = getPanelFeatures(platform, mode);

  return (
    <div className="h-full flex flex-col items-center p-8 overflow-auto">
      <div className="max-w-5xl w-full space-y-6">
        <div className="flex justify-center">
          <img src={logo} alt="logo" className="h-10 w-40" />
        </div>
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-1">
          {features.map((feature) => (
            <LauncherItem key={feature.id} feature={feature} />
          ))}
        </div>
      </div>
    </div>
  );
}

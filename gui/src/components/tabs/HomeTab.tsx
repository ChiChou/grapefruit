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
      className="w-64 flex items-center gap-3 p-3 rounded-lg hover:bg-accent transition-colors"
    >
      <div className="w-12 h-12 shrink-0 rounded-xl bg-primary/10 flex items-center justify-center text-primary">
        <Icon className="w-7 h-7" />
      </div>
      <div className="min-w-0 text-left space-y-1">
        <div className="text-[0.9rem] font-medium truncate">{title}</div>
        <div className="text-xs text-muted-foreground line-clamp-2 leading-snug">
          {t(feature.desc)}
        </div>
      </div>
    </button>
  );
}

export function HomeTab() {
  const { platform, mode } = useSession();
  const features = getPanelFeatures(platform, mode);

  return (
    <div className="h-full flex flex-col p-4 overflow-auto">
      <div className="flex flex-wrap content-start gap-2 flex-1">
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

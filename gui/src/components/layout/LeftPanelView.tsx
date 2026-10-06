import { Link, NavLink, Outlet, useLocation } from "react-router";
import { useTranslation } from "react-i18next";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { DarkmodeToggle } from "../shared/DarkmodeToggle";
import { LanguageSelector } from "../shared/LanguageSelector";
import { useSession, Mode } from "@/context/SessionContext";
import { getRouteFeatures } from "@/lib/features";

import logo from "../../assets/grapefruit.svg";

interface NavItemProps {
  to: string;
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}

function NavItem({ to, icon, label, onClick }: NavItemProps) {
  return (
    <NavLink
      to={to}
      aria-label={label}
      onClick={onClick}
      className={({ isActive }) =>
        `relative flex h-11 w-full shrink-0 items-center justify-center border-l-2 text-sidebar-foreground/60 outline-none hover:bg-sidebar-accent/50 hover:text-sidebar-foreground focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-ring/50 ${
          isActive ? "border-primary bg-sidebar-accent/50 text-sidebar-foreground" : "border-transparent"
        }`
      }
    >
      <Tooltip>
        <TooltipTrigger render={<span className="flex items-center justify-center" />}>
          {icon}
        </TooltipTrigger>
        <TooltipContent side="right">{label}</TooltipContent>
      </Tooltip>
    </NavLink>
  );
}

interface ActionNavItemProps {
  icon: React.ReactNode;
  label: string;
  onClick: () => void;
}

function ActionNavItem({ icon, label, onClick }: ActionNavItemProps) {
  return (
    <button
      type="button"
      aria-label={label}
      onClick={onClick}
      className="mx-auto flex h-9 w-9 items-center justify-center rounded-md text-sidebar-foreground/70 outline-none hover:bg-sidebar-accent hover:text-sidebar-foreground focus-visible:ring-2 focus-visible:ring-ring/50"
    >
      <Tooltip>
        <TooltipTrigger render={<span className="flex items-center justify-center" />}>
          {icon}
        </TooltipTrigger>
        <TooltipContent side="right">{label}</TooltipContent>
      </Tooltip>
    </button>
  );
}

type NavEntry =
  | { kind: "route"; route: string; icon: React.ReactNode; label: string }
  | { kind: "action"; id: string; icon: React.ReactNode; label: string; action: () => void };

export function ActivityBar({ onNavigate }: { onNavigate: () => void }) {
  const { t } = useTranslation();
  const { device, bundle, platform, mode, pid } = useSession();
  // Determine the target for URL (bundle for app mode, pid for daemon mode)
  const target = mode === Mode.App ? bundle : pid;
  const basePath = `/workspace/${platform}/${device}/${mode}/${target}`;

  const routeItems = getRouteFeatures(platform, mode);
  const navItems: NavEntry[] = routeItems.map((f) => {
    const Icon = f.icon;
    return {
      kind: "route" as const,
      route: f.route,
      icon: <Icon className="h-5 w-5" />,
      label: t(f.label),
    };
  });

  return (
    <nav aria-label={t("navigation")} className="workspace-activity native-chrome flex w-12 shrink-0 flex-col border-r border-sidebar-border bg-sidebar">
      <div className="flex h-10 shrink-0 items-center justify-center">
        <Link
          to={`/list/${device}/apps`}
          aria-label={t("apps")}
          className="flex h-9 w-9 items-center justify-center rounded-md outline-none hover:bg-sidebar-accent focus-visible:ring-2 focus-visible:ring-ring/50"
        >
          <img src={logo} alt={t("logo_alt")} className="h-6 w-6" />
        </Link>
      </div>

      {navItems.length > 0 ? (
        <div className="flex min-h-0 flex-1 flex-col overflow-y-auto">
          {navItems.map((item) =>
            item.kind === "route" ? (
              <NavItem
                key={item.route}
                to={`${basePath}/${item.route}`}
                icon={item.icon}
                label={item.label}
                onClick={onNavigate}
              />
            ) : (
              <ActionNavItem
                key={item.id}
                icon={item.icon}
                label={item.label}
                onClick={item.action}
              />
            ),
          )}
        </div>
      ) : (
        <div className="flex-1" />
      )}

      {/* Settings at bottom */}
      <div className="flex flex-col items-center gap-1 py-2">
        <LanguageSelector />
        <DarkmodeToggle />
      </div>
    </nav>
  );
}

export function LeftPanelView() {
  const { t } = useTranslation();
  const { platform, mode } = useSession();
  const { pathname } = useLocation();
  const feature = getRouteFeatures(platform, mode).find((f) =>
    pathname.endsWith(`/${f.route}`),
  );

  return (
    <aside className="flex h-full min-w-0 flex-col bg-sidebar/40">
      <div className="native-chrome flex h-8 shrink-0 items-center border-b border-border px-3 text-[11px] font-medium tracking-wide text-muted-foreground">
        {feature ? t(feature.label) : t("navigation")}
      </div>
      <div className="min-h-0 flex-1 overflow-auto"><Outlet /></div>
    </aside>
  );
}

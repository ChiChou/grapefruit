import { Link, NavLink, Outlet } from "react-router";
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
}

function NavItem({ to, icon, label }: NavItemProps) {
  return (
    <NavLink
      to={to}
      className={({ isActive }) =>
        `p-2 flex items-center justify-center hover:bg-sidebar-accent transition-colors ${
          isActive ? "bg-sidebar-accent border-l-2 border-primary" : ""
        }`
      }
    >
      <Tooltip>
        <TooltipTrigger>{icon}</TooltipTrigger>
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
    <div
      role="button"
      tabIndex={0}
      onClick={onClick}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") onClick(); }}
      className="p-2 flex items-center justify-center hover:bg-sidebar-accent transition-colors cursor-pointer"
    >
      <Tooltip>
        <TooltipTrigger>{icon}</TooltipTrigger>
        <TooltipContent side="right">{label}</TooltipContent>
      </Tooltip>
    </div>
  );
}

type NavEntry =
  | { kind: "route"; route: string; icon: React.ReactNode; label: string }
  | { kind: "action"; id: string; icon: React.ReactNode; label: string; action: () => void };

export function LeftPanelView() {
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
    <div className="flex h-full">
      <div className="w-16 bg-sidebar border-r border-sidebar-border flex flex-col">
        <div className="p-2 flex items-center justify-center border-b border-sidebar-border">
          <Link to={`/list/${device}/apps`} className="flex items-center">
            <img src={logo} alt={t("logo_alt")} className="h-6 w-6" />
          </Link>
        </div>

        {navItems.length > 0 ? (
          <div className="flex-1 flex flex-col gap-1 pt-2">
            {navItems.map((item) =>
              item.kind === "route" ? (
                <NavItem
                  key={item.route}
                  to={`${basePath}/${item.route}`}
                  icon={item.icon}
                  label={item.label}
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
        <div className="flex flex-col gap-1 py-2 items-center">
          <LanguageSelector />
          <DarkmodeToggle />
        </div>
      </div>

      <div className="flex-1 overflow-auto">
        <Outlet />
      </div>
    </div>
  );
}

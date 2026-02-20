import { Link, NavLink, Outlet } from "react-router";
import { t } from "i18next";
import {
  Info,
  Package,
  Braces,
  Link as LinkIcon,
  MapPin,
  Anchor,
  Puzzle,
  Smartphone,
} from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { DarkmodeToggle } from "../shared/DarkmodeToggle";
import { LanguageSelector } from "../shared/LanguageSelector";
import { useSession, Platform, Mode } from "@/context/SessionContext";

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
  const { device, bundle, platform, mode, pid } = useSession();
  // Determine the target for URL (bundle for app mode, pid for daemon mode)
  const target = mode === Mode.App ? bundle : pid;
  const basePath = `/workspace/${platform}/${device}/${mode}/${target}`;

  const navKey = `${platform}:${mode}`;
  const navItems: NavEntry[] = ({
    [`${Platform.Fruity}:${Mode.App}`]: [
      { kind: "route", route: "general", icon: <Info className="h-5 w-5" />, label: t("general") },
      { kind: "route", route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { kind: "route", route: "classes", icon: <Braces className="h-5 w-5" />, label: t("classes") },
      { kind: "route", route: "urls", icon: <LinkIcon className="h-5 w-5" />, label: "URL Schemes" },
      { kind: "route", route: "hooks", icon: <Anchor className="h-5 w-5" />, label: t("hooks") },
      { kind: "route", route: "device", icon: <Smartphone className="h-5 w-5" />, label: t("device_info") },
      { kind: "route", route: "geolocation", icon: <MapPin className="h-5 w-5" />, label: t("geolocation_simulation") },
    ],
    [`${Platform.Fruity}:${Mode.Daemon}`]: [
      { kind: "route", route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { kind: "route", route: "classes", icon: <Braces className="h-5 w-5" />, label: t("classes") },
      { kind: "route", route: "hooks", icon: <Anchor className="h-5 w-5" />, label: t("hooks") },
      { kind: "route", route: "device", icon: <Smartphone className="h-5 w-5" />, label: t("device_info") },
    ],
    [`${Platform.Droid}:${Mode.App}`]: [
      { kind: "route", route: "general", icon: <Info className="h-5 w-5" />, label: t("general") },
      { kind: "route", route: "components", icon: <Puzzle className="h-5 w-5" />, label: t("components") },
      { kind: "route", route: "classes", icon: <Braces className="h-5 w-5" />, label: t("classes") },
      { kind: "route", route: "urls", icon: <LinkIcon className="h-5 w-5" />, label: "URL Schemes" },
      { kind: "route", route: "hooks", icon: <Anchor className="h-5 w-5" />, label: t("hooks") },
      { kind: "route", route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { kind: "route", route: "device", icon: <Smartphone className="h-5 w-5" />, label: t("device_info") },
    ],
    [`${Platform.Droid}:${Mode.Daemon}`]: [
      { kind: "route", route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { kind: "route", route: "classes", icon: <Braces className="h-5 w-5" />, label: t("classes") },
      { kind: "route", route: "hooks", icon: <Anchor className="h-5 w-5" />, label: t("hooks") },
      { kind: "route", route: "device", icon: <Smartphone className="h-5 w-5" />, label: t("device_info") },
    ],
  } satisfies Record<string, NavEntry[]>)[navKey] ?? [];

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

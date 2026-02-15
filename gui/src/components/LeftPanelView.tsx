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
  MessageSquare,
} from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { DarkmodeToggle } from "./DarkmodeToggle";
import { LanguageSelector } from "./LanguageSelector";
import { useSession, Platform, Mode } from "@/context/SessionContext";

import logo from "../assets/grapefruit.svg";

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

export function LeftPanelView() {
  const { device, bundle, platform, mode, pid } = useSession();

  // Determine the target for URL (bundle for app mode, pid for daemon mode)
  const target = mode === Mode.App ? bundle : pid;
  const basePath = `/workspace/${platform}/${device}/${mode}/${target}`;

  const navKey = `${platform}:${mode}`;
  const navItems: { route: string; icon: React.ReactNode; label: string }[] = {
    [`${Platform.Fruity}:${Mode.App}`]: [
      { route: "general", icon: <Info className="h-5 w-5" />, label: t("general") },
      { route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { route: "classes", icon: <Braces className="h-5 w-5" />, label: t("classes") },
      { route: "urls", icon: <LinkIcon className="h-5 w-5" />, label: "URL Schemes" },
      { route: "hooks", icon: <Anchor className="h-5 w-5" />, label: t("hooks") },
      { route: "flutter", icon: <MessageSquare className="h-5 w-5" />, label: t("flutter") },
      { route: "geolocation", icon: <MapPin className="h-5 w-5" />, label: t("geolocation_simulation") },
    ],
    [`${Platform.Fruity}:${Mode.Daemon}`]: [
      { route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { route: "classes", icon: <Braces className="h-5 w-5" />, label: t("classes") },
      { route: "hooks", icon: <Anchor className="h-5 w-5" />, label: t("hooks") },
      { route: "flutter", icon: <MessageSquare className="h-5 w-5" />, label: t("flutter") },
    ],
    [`${Platform.Droid}:${Mode.App}`]: [
      { route: "general", icon: <Info className="h-5 w-5" />, label: t("general") },
      { route: "components", icon: <Puzzle className="h-5 w-5" />, label: t("components") },
      { route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { route: "device", icon: <Smartphone className="h-5 w-5" />, label: t("device_info") },
      { route: "flutter", icon: <MessageSquare className="h-5 w-5" />, label: t("flutter") },
    ],
    [`${Platform.Droid}:${Mode.Daemon}`]: [
      { route: "modules", icon: <Package className="h-5 w-5" />, label: t("modules") },
      { route: "device", icon: <Smartphone className="h-5 w-5" />, label: t("device_info") },
      { route: "flutter", icon: <MessageSquare className="h-5 w-5" />, label: t("flutter") },
    ],
  }[navKey] ?? [];

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
            {navItems.map((item) => (
              <NavItem
                key={item.route}
                to={`${basePath}/${item.route}`}
                icon={item.icon}
                label={item.label}
              />
            ))}
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

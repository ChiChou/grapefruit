import { Link, NavLink, Outlet } from "react-router";
import { t } from "i18next";
import { Info, Package, Braces, Link as LinkIcon, MapPin, Webhook } from "lucide-react";

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
        `p-2 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors ${
          isActive
            ? "bg-gray-200 dark:bg-gray-800 border-l-2 border-primary"
            : ""
        }`
      }
    >
      <Tooltip>
        <TooltipTrigger asChild>{icon}</TooltipTrigger>
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

  // Determine which navigation to show based on platform and mode
  const isFruityApp = platform === Platform.Fruity && mode === Mode.App;
  const isFruityDaemon = platform === Platform.Fruity && mode === Mode.Daemon;

  const renderNavigation = () => {
    if (isFruityApp) {
      // iOS App mode - full features
      return (
        <div className="flex-1 flex flex-col gap-1 pt-2">
          <NavItem
            to={`${basePath}/general`}
            icon={<Info className="h-5 w-5" />}
            label={t("general")}
          />
          <NavItem
            to={`${basePath}/modules`}
            icon={<Package className="h-5 w-5" />}
            label={t("modules")}
          />
          <NavItem
            to={`${basePath}/classes`}
            icon={<Braces className="h-5 w-5" />}
            label={t("classes")}
          />
          <NavItem
            to={`${basePath}/urls`}
            icon={<LinkIcon className="h-5 w-5" />}
            label="URL Schemes"
          />
          <NavItem
            to={`${basePath}/geolocation`}
            icon={<MapPin className="h-5 w-5" />}
            label={t("geolocation_simulation")}
          />
          <NavItem
            to={`${basePath}/hooks`}
            icon={<Webhook className="h-5 w-5" />}
            label={t("hooks")}
          />
        </div>
      );
    }

    if (isFruityDaemon) {
      // iOS Daemon mode - modules, classes, hooks
      return (
        <div className="flex-1 flex flex-col gap-1 pt-2">
          <NavItem
            to={`${basePath}/modules`}
            icon={<Package className="h-5 w-5" />}
            label={t("modules")}
          />
          <NavItem
            to={`${basePath}/classes`}
            icon={<Braces className="h-5 w-5" />}
            label={t("classes")}
          />
          <NavItem
            to={`${basePath}/hooks`}
            icon={<Webhook className="h-5 w-5" />}
            label={t("hooks")}
          />
        </div>
      );
    }

    // Other modes - no navigation yet
    return <div className="flex-1" />;
  };

  // Show panel content for modes with full workspace (left panel + tabs area)
  const showPanelContent = isFruityApp || isFruityDaemon;

  return (
    <div className="flex h-full">
      <div className="w-12 bg-gray-50 dark:bg-gray-900 border-r dark:border-gray-700 flex flex-col">
        <div className="p-2 flex items-center justify-center border-b dark:border-gray-700">
          <Link to={`/list/${device}/apps`} className="flex items-center">
            <img src={logo} alt={t("logo_alt")} className="h-6 w-6" />
          </Link>
        </div>

        {renderNavigation()}

        {/* Settings at bottom */}
        <div className="flex flex-col gap-1 py-2 items-center">
          <LanguageSelector />
          <DarkmodeToggle />
        </div>
      </div>

      {/* Tab content for modes with panel + tabs layout */}
      {showPanelContent && (
        <div className="flex-1 overflow-auto">
          <Outlet />
        </div>
      )}
    </div>
  );
}

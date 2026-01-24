import { Link, NavLink, Outlet } from "react-router";
import { t } from "i18next";
import { Info, Package, Braces, Globe } from "lucide-react";

import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "@/components/ui/tooltip";
import { DarkmodeToggle } from "./DarkmodeToggle";
import { LanguageSelector } from "./LanguageSelector";
import { useSession } from "@/context/SessionContext";

import logo from "../assets/grapefruit.svg";

export function LeftPanelView() {
  const { device, bundle } = useSession();

  return (
    <div className="flex h-full">
      <div className="w-12 bg-gray-50 dark:bg-gray-900 border-r dark:border-gray-700 flex flex-col">
        <div className="p-2 flex items-center justify-center border-b dark:border-gray-700">
          <Link to={`/apps/${device}`} className="flex items-center">
            <img src={logo} alt={t("logo_alt")} className="h-6 w-6" />
          </Link>
        </div>

        <div className="flex-1 flex flex-col gap-1 pt-2">
          <NavLink
            to={`/workspace/${device}/${bundle}/general`}
            className={({ isActive }) =>
              `p-2 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors ${
                isActive
                  ? "bg-gray-200 dark:bg-gray-800 border-l-2 border-primary"
                  : ""
              }`
            }
          >
            <Tooltip>
              <TooltipTrigger asChild>
                <Info className="h-5 w-5" />
              </TooltipTrigger>
              <TooltipContent side="right">{t("general")}</TooltipContent>
            </Tooltip>
          </NavLink>

          <NavLink
            to={`/workspace/${device}/${bundle}/modules`}
            className={({ isActive }) =>
              `p-2 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors ${
                isActive
                  ? "bg-gray-200 dark:bg-gray-800 border-l-2 border-primary"
                  : ""
              }`
            }
          >
            <Tooltip>
              <TooltipTrigger asChild>
                <Package className="h-5 w-5" />
              </TooltipTrigger>
              <TooltipContent side="right">{t("modules")}</TooltipContent>
            </Tooltip>
          </NavLink>

          <NavLink
            to={`/workspace/${device}/${bundle}/classes`}
            className={({ isActive }) =>
              `p-2 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors ${
                isActive
                  ? "bg-gray-200 dark:bg-gray-800 border-l-2 border-primary"
                  : ""
              }`
            }
          >
            <Tooltip>
              <TooltipTrigger asChild>
                <Braces className="h-5 w-5" />
              </TooltipTrigger>
              <TooltipContent side="right">{t("classes")}</TooltipContent>
            </Tooltip>
          </NavLink>

          <NavLink
            to={`/workspace/${device}/${bundle}/urls`}
            className={({ isActive }) =>
              `p-2 flex items-center justify-center hover:bg-gray-200 dark:hover:bg-gray-800 transition-colors ${
                isActive
                  ? "bg-gray-200 dark:bg-gray-800 border-l-2 border-primary"
                  : ""
              }`
            }
          >
            <Tooltip>
              <TooltipTrigger asChild>
                <Globe className="h-5 w-5" />
              </TooltipTrigger>
              <TooltipContent side="right">URL Schemes</TooltipContent>
            </Tooltip>
          </NavLink>
        </div>

        {/* Settings at bottom */}
        <div className="flex flex-col gap-1 py-2 items-center">
          <LanguageSelector />
          <DarkmodeToggle />
        </div>
      </div>

      {/* Tab content */}
      <div className="flex-1 overflow-auto">
        <Outlet />
      </div>
    </div>
  );
}

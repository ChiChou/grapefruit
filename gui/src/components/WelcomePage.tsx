import { useTranslation } from "react-i18next";
import { Link, Outlet } from "react-router";

import logo from "../assets/logo.svg";
import { Devices } from "./Devices";
import { DarkmodeToggle } from "./DarkmodeToggle";
import { LanguageSelector } from "./LanguageSelector";

export function WelcomePage() {
  const { t } = useTranslation();

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden sm:flex-row">
      <div className="flex w-full flex-col border-b border-gray-200 bg-gray-50 p-4 dark:border-gray-700 dark:bg-gray-900 sm:h-full sm:w-64 sm:border-b-0 sm:border-r">
        <div className="mb-6 flex items-center justify-center gap-2 px-4">
          <Link to="/">
            <img src={logo} alt={t("logo_alt")} className="h-10 w-40" />
          </Link>
        </div>
        <div className="mb-4">
          <Devices />
        </div>
        <footer className="mt-auto flex items-center gap-2 pt-4">
          <LanguageSelector />
          <DarkmodeToggle />
        </footer>
      </div>
      <main className="flex-1 overflow-auto">
        <Outlet />
      </main>
    </div>
  );
}

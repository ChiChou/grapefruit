import { useTranslation } from "react-i18next";
import { Link, Outlet } from "react-router";
import { Binary } from "lucide-react";
import { SiReact } from "@icons-pack/react-simple-icons";

import logo from "../../assets/logo.svg";
import { Devices } from "./Devices";
import { DarkmodeToggle } from "../shared/DarkmodeToggle";
import { LanguageSelector } from "../shared/LanguageSelector";

export function WelcomePage() {
  const { t } = useTranslation();

  return (
    <div className="flex h-screen w-screen flex-col overflow-hidden sm:flex-row">
      <div className="flex w-full flex-col border-b border-border bg-sidebar sm:h-full sm:w-64 sm:border-b-0 sm:border-r">
        <div className="flex items-center justify-center px-4 py-5">
          <Link to="/">
            <img src={logo} alt={t("logo_alt")} className="h-10 w-40" />
          </Link>
        </div>

        {/* Devices */}
        <div className="flex-1 overflow-auto px-4">
          <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-2">
            {t("devices")}
          </p>
          <Devices />
        </div>

        {/* Tools */}
        <div className="px-4 py-3 border-t border-border">
          <p className="text-[10px] font-medium text-muted-foreground uppercase tracking-wider mb-2">
            {t("decompiler")}
          </p>
          <div className="flex flex-col gap-0.5">
            <Link
              to="/decompiler/hermes"
              className="flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            >
              <SiReact className="h-4 w-4 shrink-0" />
              {t("decompiler_hermes")}
            </Link>
            <Link
              to="/decompiler/radare2"
              className="flex items-center gap-2.5 rounded-md px-2.5 py-2 text-sm text-muted-foreground hover:text-foreground hover:bg-accent transition-colors"
            >
              <Binary className="h-4 w-4 shrink-0" />
              {t("decompiler_r2")}
            </Link>
          </div>
        </div>

        {/* Footer */}
        <footer className="flex items-center gap-2 px-4 py-3 border-t border-border">
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

import { useTranslation } from "react-i18next";
import { SunIcon, MoonIcon } from "lucide-react";

import { useTheme } from "./theme-provider";

import { Button } from "./ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "./ui/tooltip";

export function DarkmodeToggle() {
  const { theme, setTheme } = useTheme();

  const toggleDarkMode = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };

  const { t } = useTranslation();

  return (
    <Tooltip>
      <TooltipContent>{t("toggle_dark_mode")}</TooltipContent>
      <TooltipTrigger asChild>
        <Button
          variant="ghost"
          size="icon"
          onClick={toggleDarkMode}
          aria-label={t("toggle_dark_mode")}
        >
          {theme === "dark" ? (
            <SunIcon className="h-5 w-5" />
          ) : (
            <MoonIcon className="h-5 w-5" />
          )}
        </Button>
      </TooltipTrigger>
    </Tooltip>
  );
}

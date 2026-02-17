import { useTranslation } from "react-i18next";
import { SunIcon, MoonIcon } from "lucide-react";

import { useTheme } from "../providers/ThemeProvider";

import { Button } from "../ui/button";
import { Tooltip, TooltipContent, TooltipTrigger } from "../ui/tooltip";

export function DarkmodeToggle() {
  const { theme, setTheme } = useTheme();

  const toggleDarkMode = () => {
    setTheme(theme === "dark" ? "light" : "dark");
  };

  const { t } = useTranslation();

  return (
    <Tooltip>
      <TooltipContent>{t("toggle_dark_mode")}</TooltipContent>
      <TooltipTrigger
        render={
          <Button
            variant="outline"
            size="icon"
            onClick={toggleDarkMode}
            aria-label={t("toggle_dark_mode")}
          />
        }
      >
        {theme === "dark" ? (
          <SunIcon className="h-5 w-5" />
        ) : (
          <MoonIcon className="h-5 w-5" />
        )}
      </TooltipTrigger>
    </Tooltip>
  );
}

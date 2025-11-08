import { useTranslation } from "react-i18next";
import { Tooltip, TooltipContent, TooltipTrigger } from "./ui/tooltip";

export function LanguageSelector() {
  const { t, i18n } = useTranslation();

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <select
          value={i18n.language}
          onChange={(e) => changeLanguage(e.target.value)}
          className="flex-1 rounded-md border border-gray-300 bg-white px-3 py-2 text-sm dark:border-gray-600 dark:bg-gray-800 dark:text-gray-100"
          aria-label={t("select_language")}
        >
          <option value="en">{t("language_en")}</option>
          <option value="cn">{t("language_cn")}</option>
        </select>
      </TooltipTrigger>
      <TooltipContent>{t("select_language")}</TooltipContent>
    </Tooltip>
  );
}

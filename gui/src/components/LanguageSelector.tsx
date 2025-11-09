import { useTranslation } from "react-i18next";
import { Check, Languages } from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "./ui/dropdown-menu";
import { Button } from "./ui/button";

export function LanguageSelector() {
  const { t, i18n } = useTranslation();

  const changeLanguage = (lng: string) => {
    i18n.changeLanguage(lng);
  };

  const languages = [
    { value: "en", label: t("language_en") },
    { value: "cn", label: t("language_cn") },
  ];

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button variant="outline" size="icon" className="gap-2">
          <Languages />
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="start">
        {languages.map((lang) => (
          <DropdownMenuItem
            key={lang.value}
            onClick={() => changeLanguage(lang.value)}
            className="gap-2"
          >
            {lang.value === i18n.language && <Check className="h-4 w-4" />}
            {lang.value !== i18n.language && <span className="w-4" />}
            {lang.label}
          </DropdownMenuItem>
        ))}
      </DropdownMenuContent>
    </DropdownMenu>
  );
}
